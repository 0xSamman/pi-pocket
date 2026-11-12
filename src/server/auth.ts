import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { type ConfigStore, newToken, type Role, type User } from "./config.ts";
import { HttpError } from "./errors.ts";

export const COOKIE = "pocket_auth";

/** How long an invite may last, in minutes: 15 minutes (the default, and always for an owner invite), an hour, a day, or a week. */
export const INVITE_MINUTES = [15, 60, 24 * 60, 7 * 24 * 60] as const;
export type InviteMinutes = (typeof INVITE_MINUTES)[number];

export function parseCookies(header: string | undefined): Record<string, string> {
    const out: Record<string, string> = {};

    for (const part of (header ?? "").split(";")) {
        const index = part.indexOf("=");

        if (index <= 0) {
            continue;
        }

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        try {
            out[key] = decodeURIComponent(value);
        } catch {
            out[key] = value;
        }
    }

    return out;
}

/** https when the request came through TLS or a TLS-terminating tunnel such as ngrok or Tailscale Funnel. */
function isHttps(request: IncomingMessage): boolean {
    const forwarded = String(request.headers["x-forwarded-proto"] ?? "")
        .split(",")[0]
        ?.trim();

    return forwarded === "https" || (request.socket as { encrypted?: boolean }).encrypted === true;
}

export function origin(request: IncomingMessage): string {
    const host = String(request.headers["x-forwarded-host"] ?? request.headers.host ?? "localhost");

    return `${isHttps(request) ? "https" : "http"}://${host}`;
}

/** The Cloudflare quick tunnel host a request came through, such as `abc-def.trycloudflare.com`, if it did. */
export function quickTunnelHost(request: IncomingMessage): string | undefined {
    const host = String(request.headers["x-forwarded-host"] ?? request.headers.host ?? "")
        .toLowerCase()
        .replace(/:\d+$/, "");

    return /^[a-z0-9-]+\.trycloudflare\.com$/.test(host) ? host : undefined;
}

export function setAuthCookie(
    request: IncomingMessage,
    response: ServerResponse,
    token: string,
): void {
    const parts = [
        `${COOKIE}=${encodeURIComponent(token)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        `Max-Age=${60 * 60 * 24 * 365}`,
        ...(isHttps(request) ? ["Secure"] : []),
    ];

    response.setHeader("set-cookie", parts.join("; "));
}

export function clearAuthCookie(response: ServerResponse): void {
    response.setHeader("set-cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

/**
 * What an invite grants: a role, and optionally a single session instead of all of them. An owner invite signs a device
 * in as the owner, with the owner's token: it is never for one session.
 */
export type InviteGrant =
    | { role: Exclude<Role, "owner">; session?: string }
    | { role: "owner"; session?: never }
    | { role: "device"; targetId?: string; name?: string; session?: never };

/** Invites live in `config.json` (by their codes' hashes), so one that lasts a day or a week outlives a restart. */
export class Auth {
    readonly #config: ConfigStore;

    constructor(config: ConfigStore) {
        this.#config = config;
    }

    user(request: IncomingMessage): User | undefined {
        const token = parseCookies(request.headers.cookie)[COOKIE];

        if (token === undefined || token === "") {
            const bearer = String(request.headers.authorization ?? "");

            if (bearer.startsWith("Bearer ")) {
                return this.#config.userByToken(bearer.slice(7).trim());
            }

            return undefined;
        }

        return this.#config.userByToken(token);
    }

    tokenUser(token: string): User | undefined {
        return this.#config.userByToken(token);
    }

    /** A new invite that lasts `minutes`; an owner invite always lasts 15, the least. */
    createInvite(
        by: User,
        grant: InviteGrant = { role: "guest" },
        minutes: InviteMinutes = 15,
    ): { code: string; proof: string; expiresAt: number; minutes: InviteMinutes } {
        if (
            grant.role === "owner" &&
            ("session" in grant ||
                "targetId" in grant ||
                "team" in grant ||
                "teamRole" in grant ||
                "admin" in grant)
        ) {
            throw new HttpError(400, "An owner invitation cannot change account access.");
        }

        if (grant.role === "device") {
            const creator = this.#config.userById(by.id);
            const target = this.#config.userById(grant.targetId ?? by.id);

            if (
                grant.session !== undefined ||
                "team" in grant ||
                "teamRole" in grant ||
                "admin" in grant
            ) {
                throw new HttpError(400, "A device invitation cannot change account access.");
            }

            if (!this.canPair(creator, target)) {
                throw new HttpError(403, "You cannot sign in a device for this account.");
            }

            if (target!.role !== "owner" && (target!.tokenHashes?.length ?? 0) >= 10) {
                throw new HttpError(
                    409,
                    "This account has 10 additional devices. Existing devices remain signed in.",
                );
            }
        }

        if (grant.role === "device" || grant.role === "owner") {
            const creator = this.#config.userById(by.id);

            if (
                this.#config.devicePairingBlocked ||
                creator === undefined ||
                (grant.role === "owner" && creator.role !== "owner")
            ) {
                throw new HttpError(403, "Only the owner can issue an owner invitation.");
            }

            const times = (creator.deviceInviteTimes ?? []).filter(
                (time) => time > Date.now() - 15 * 60_000,
            );

            if (times.length >= 5) {
                throw new HttpError(429, "Wait 15 minutes before making more device invitations.");
            }

            creator.deviceInviteTimes = [...times, Date.now()];
            this.#config.save();
        }

        // Unambiguous characters, easy to type on a phone.
        const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
        const bytes = randomBytes(10);
        let code = "";

        for (const byte of bytes) {
            code += alphabet[byte % alphabet.length];
        }

        const lasts =
            grant.role === "owner" || grant.role === "device" ? INVITE_MINUTES[0] : minutes;
        const expiresAt = Date.now() + lasts * 60_000;

        this.#config.addInvite(code, {
            ...grant,
            expiresAt,
            createdBy: by.id,
            ...(grant.role === "device" || grant.role === "owner"
                ? {
                      targetId: grant.role === "device" ? (grant.targetId ?? by.id) : by.id,
                      creatorAccess: this.#config.deviceAccess(by.id),
                      targetAccess: this.#config.deviceAccess(
                          grant.role === "device" ? (grant.targetId ?? by.id) : by.id,
                      ),
                  }
                : {}),
        });

        return { code, proof: this.inviteProof(code), expiresAt, minutes: lasts };
    }

    private inviteProof(code: string): string {
        return createHmac("sha256", this.#config.ownerToken)
            .update("pi-pocket:invite-proof:v1\0")
            .update(code)
            .digest("hex");
    }

    /** Check a link's capability without looking up the invitation. */
    validInviteProof(code: string, proof: string | null): boolean {
        if (proof === null || !/^[a-f0-9]{64}$/.test(proof)) {
            return false;
        }

        return timingSafeEqual(
            Buffer.from(proof, "hex"),
            Buffer.from(this.inviteProof(code), "hex"),
        );
    }

    /** A person can pair themselves; only the owner can pair another person. */
    canPair(by: User | undefined, target: User | undefined): boolean {
        return (
            !this.#config.devicePairingBlocked &&
            by !== undefined &&
            target !== undefined &&
            (by.id === target.id ||
                (by.role === "owner" && by.sessions === undefined && target.role !== "owner"))
        );
    }

    /** End an invite before its time, if `by` made it: when the sheet that showed it moves on to another. */
    cancelInvite(code: string, by: User): void {
        if (this.#config.invite(code)?.createdBy === by.id) {
            this.#config.removeInvite(code);
        }
    }

    /** The grant of a live invite, or undefined when it expired or was used. */
    invite(code: string): InviteGrant | undefined {
        const invite = this.#config.invite(code);

        if (invite === undefined) {
            return undefined;
        }

        if (
            invite.role === "owner" &&
            (this.#config.devicePairingBlocked ||
                this.#config.userById(invite.createdBy)?.role !== "owner")
        ) {
            return undefined;
        }

        if (invite.role === "device") {
            const creator = this.#config.userById(invite.createdBy);
            const target = this.#config.userById(invite.targetId ?? invite.createdBy);

            return this.canPair(creator, target)
                ? { role: "device", targetId: target!.id, name: target!.name }
                : undefined;
        }

        return invite.role === "owner" || invite.session === undefined
            ? { role: invite.role }
            : { role: invite.role, session: invite.session };
    }

    inviteValid(code: string): boolean {
        return this.invite(code) !== undefined;
    }

    /**
     * Spend an invite on a new device: a user with the invite's role and scope, and its own token. An owner invite makes
     * no one new: the device gets the owner and the owner's token. Either way the invite is gone, used or not.
     */
    redeem(code: string, name: string): { user: User; token: string } | undefined {
        const invite = this.#config.invite(code);

        if (invite === undefined || !this.#config.removeInvite(code)) {
            return undefined;
        }

        // The person who made it must still be allowed to: not removed, not view only, not limited to one session.
        const creator = this.#config.userById(invite.createdBy);

        if (creator === undefined) {
            return undefined;
        }

        if (invite.role === "device") {
            const target = this.#config.userById(invite.targetId ?? invite.createdBy);

            if (!this.canPair(creator, target)) {
                return undefined;
            }

            if (target!.role === "owner") {
                return { user: target!, token: this.#config.ownerToken };
            }

            const token = newToken();

            return this.#config.addUserToken(target!.id, token)
                ? { user: target!, token }
                : undefined;
        }

        if (creator.role === "viewer" || creator.sessions !== undefined) {
            return undefined;
        }

        if (invite.role === "owner") {
            return !this.#config.devicePairingBlocked && creator.role === "owner"
                ? { user: creator, token: this.#config.ownerToken }
                : undefined;
        }

        const clean = name.replace(/\s+/g, " ").trim().slice(0, 40) || "Guest";

        return this.#config.addUser(
            clean,
            invite.role,
            invite.session === undefined ? undefined : [invite.session],
        );
    }
}
