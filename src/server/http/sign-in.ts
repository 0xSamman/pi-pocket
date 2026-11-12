/** The pages outside the app: signing in with a link, joining with an invite, and a share that arrived too early. */
import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { PocketApp } from "../app.ts";
import { type Auth, origin, quickTunnelHost, setAuthCookie } from "../auth.ts";
import { HttpError } from "../errors.ts";
import { conversationId, escapeHtml, readBody, send } from "./io.ts";

/** A form posted from another site, as browsers report it. Such a post must not sign this browser in or out. */
function crossSite(request: IncomingMessage): boolean {
    const site = request.headers["sec-fetch-site"];

    if (site !== undefined && site !== "same-origin" && site !== "none") {
        return true;
    }

    const supplied = request.headers.origin;

    if (supplied === undefined) {
        return site === undefined;
    }

    // A no-referrer form can send an opaque Origin even on this origin.
    if (supplied === "null") {
        return site !== "same-origin";
    }

    try {
        const actual = new URL(supplied);
        const expected = new URL(origin(request));

        return supplied !== actual.origin || actual.origin !== expected.origin;
    } catch {
        return true;
    }
}

/** Where to go after signing in: a path on this server, never `//host` or `/\host`, which browsers read as another site. */
function localPath(next: string | null): string {
    return next !== null && /^\/(?![/\\])/.test(next) ? next : "/";
}

function page(title: string, body: string): string {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/style.css"></head><body class="plain-page"><main class="plain">${body}</main></body></html>`;
}

/** `/login`: sign this browser in with a token from a link, after asking when it would switch accounts. */
export async function login(
    auth: Auth,
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
): Promise<void> {
    const posted = request.method === "POST";

    if (posted && crossSite(request)) {
        throw new HttpError(403, "Sign in from Pi Pocket's own page.");
    }

    const form = posted
        ? new URLSearchParams((await readBody(request, 10_000)).toString("utf8"))
        : url.searchParams;
    const token = form.get("token") ?? "";
    const next = localPath(form.get("next"));
    const signingIn = auth.tokenUser(token);

    if (signingIn === undefined) {
        return send(
            response,
            401,
            page(
                "Pi Pocket",
                `<h1>Link expired</h1><p>That login link is not valid. Use the link Pi Pocket prints when it starts, or ask someone signed in for a new invite.</p>`,
            ),
            "text/html; charset=utf-8",
        );
    }

    const current = auth.user(request);

    if (!posted && current !== undefined && current.id !== signingIn.id) {
        // Signed in as someone else: switching takes a tap, so a link on another site cannot do it unnoticed.
        return send(
            response,
            200,
            page(
                "Switch account? · Pi Pocket",
                `<h1>Switch account?</h1><p>This browser is signed in as ${escapeHtml(current.name)}. The link you opened signs it in as ${escapeHtml(signingIn.name)} instead.</p><form method="post" action="/login"><input type="hidden" name="token" value="${escapeHtml(token)}"><input type="hidden" name="next" value="${escapeHtml(next)}"><button type="submit">Sign in as ${escapeHtml(signingIn.name)}</button></form><p><a href="/">Stay signed in as ${escapeHtml(current.name)}</a></p>`,
            ),
            "text/html; charset=utf-8",
            { "referrer-policy": "no-referrer" },
        );
    }

    setAuthCookie(request, response, token);
    response.writeHead(303, { location: next });
    response.end();

    return;
}

// Preview and redemption both check a code. A per-code bucket limits retries without
// letting random invalid codes exhaust the small allowance for another link behind a proxy.
// A link's proof bypasses the larger discovery limit without looking up the code.
const INVITE_WINDOW_MS = 10 * 60_000;
const INVITE_ATTEMPTS = 30;
const INVITE_SOCKET_ATTEMPTS = 3000;
const INVITE_BUCKETS = 4096;

type InviteBucket = { count: number; until: number };
const inviteSockets = new Map<string, InviteBucket>();
const inviteCodes = new Map<string, InviteBucket>();
const provedInviteCodes = new Map<string, InviteBucket>();

function consumeInviteBucket(
    buckets: Map<string, InviteBucket>,
    key: string,
    limit: number,
    now: number,
    evict: boolean,
): number | undefined {
    let entry = buckets.get(key);

    if (entry !== undefined && entry.until <= now) {
        buckets.delete(key);
        entry = undefined;
    }

    if (entry === undefined) {
        if (buckets.size >= INVITE_BUCKETS) {
            for (const [oldKey, value] of buckets) {
                if (value.until <= now) {
                    buckets.delete(oldKey);
                }
            }
        }

        if (buckets.size >= INVITE_BUCKETS) {
            if (!evict) {
                return Math.ceil(INVITE_WINDOW_MS / 1000);
            }

            // Code buckets may be evicted; invalid guesses still face the socket limit.
            buckets.delete(buckets.keys().next().value!);
        }

        entry = { count: 0, until: now + INVITE_WINDOW_MS };
        buckets.set(key, entry);
    }

    if (entry.count >= limit) {
        return Math.max(1, Math.ceil((entry.until - now) / 1000));
    }

    entry.count++;

    return undefined;
}

function inviteCodeRetryAfter(
    request: IncomingMessage,
    code: string,
    proved: boolean,
): number | undefined {
    const address = request.socket.remoteAddress ?? "unknown";
    const now = Date.now();
    // Do not keep invitation codes in memory or use an unbounded key from the URL.
    const unsignedKey = createHash("sha256")
        .update(JSON.stringify([address, code]))
        .digest("hex");
    const key = createHash("sha256").update(code).digest("hex");
    const protectedEntry = provedInviteCodes.get(key);

    if (protectedEntry !== undefined && protectedEntry.until <= now) {
        provedInviteCodes.delete(key);
    }

    if (proved && !provedInviteCodes.has(key)) {
        if (provedInviteCodes.size >= INVITE_BUCKETS) {
            for (const [oldKey, value] of provedInviteCodes) {
                if (value.until <= now) {
                    provedInviteCodes.delete(oldKey);
                }
            }
        }

        if (provedInviteCodes.size >= INVITE_BUCKETS) {
            return Math.ceil(INVITE_WINDOW_MS / 1000);
        }

        const existing = inviteCodes.get(unsignedKey);

        if (existing !== undefined && existing.until > now) {
            provedInviteCodes.set(key, existing);
        }

        inviteCodes.delete(unsignedKey);
    }

    const protectedBucket = proved || provedInviteCodes.has(key);

    return consumeInviteBucket(
        protectedBucket ? provedInviteCodes : inviteCodes,
        protectedBucket ? key : unsignedKey,
        INVITE_ATTEMPTS,
        now,
        !protectedBucket,
    );
}

function inviteDiscoveryRetryAfter(request: IncomingMessage): number | undefined {
    const address = request.socket.remoteAddress ?? "unknown";

    return consumeInviteBucket(inviteSockets, address, INVITE_SOCKET_ATTEMPTS, Date.now(), false);
}

/** `/join/:code`: what an invite grants, and redeeming it with a name (or, for an owner invite, signing in as the owner). */
export async function join(
    app: PocketApp,
    auth: Auth,
    request: IncomingMessage,
    response: ServerResponse,
    code: string,
): Promise<void> {
    if (request.method === "POST" && crossSite(request)) {
        throw new HttpError(403, "Join from Pi Pocket's own page.");
    }

    const proof = new URL(request.url ?? "/", "http://localhost").searchParams.get("proof");
    const proved = auth.validInviteProof(code, proof);
    // A spent or expired signed link must not occupy a protected bucket.
    let grant = proved ? auth.invite(code) : undefined;

    if (proved && grant === undefined) {
        return send(
            response,
            410,
            page("Pi Pocket", "<h1>Invite expired</h1><p>Ask for a new one.</p>"),
            "text/html; charset=utf-8",
        );
    }

    let retryAfter = proved ? undefined : inviteDiscoveryRetryAfter(request);

    if (retryAfter === undefined) {
        retryAfter = inviteCodeRetryAfter(request, code, proved);
    }

    if (retryAfter !== undefined) {
        return send(
            response,
            429,
            page("Pi Pocket", "<h1>Too many attempts</h1><p>Try again later.</p>"),
            "text/html; charset=utf-8",
            { "retry-after": String(retryAfter) },
        );
    }

    if (!proved) {
        grant = auth.invite(code);
    }

    if (request.method === "POST") {
        const form = new URLSearchParams((await readBody(request, 10_000)).toString("utf8"));
        const redeemed = auth.redeem(code, form.get("name") ?? "");

        if (redeemed === undefined) {
            return send(
                response,
                410,
                page("Pi Pocket", "<h1>Invite expired</h1><p>Ask for a new one.</p>"),
                "text/html; charset=utf-8",
            );
        }

        const tunnel = quickTunnelHost(request);

        // The owner is never tied to one tunnel.
        if (tunnel !== undefined && redeemed.user.role !== "owner" && grant?.role !== "device") {
            app.config.updateUser(redeemed.user.id, { tunnel });
        }

        setAuthCookie(request, response, redeemed.token);
        response.writeHead(303, { location: "/" });
        response.end();

        return;
    }

    if (grant === undefined) {
        return send(
            response,
            410,
            page(
                "Pi Pocket",
                "<h1>Invite expired</h1><p>Each invite works once, and only until it expires. Ask for a new one.</p>",
            ),
            "text/html; charset=utf-8",
        );
    }

    if (grant.role === "owner") {
        const current = auth.user(request);
        // Signed in as someone else: say so, as switching accounts does.
        const switching =
            current !== undefined && current.role !== "owner"
                ? `<p>This browser is signed in as ${escapeHtml(current.name)}. It will change to the owner.</p>`
                : "";

        return send(
            response,
            200,
            page(
                "Sign in as owner · Pi Pocket",
                `<h1>Sign in as owner</h1><p>This device will sign in as you, the owner. It gets full control of Pi Pocket and of this machine.</p>${switching}<form method="post"><button type="submit">Sign in as owner</button></form>`,
            ),
            "text/html; charset=utf-8",
            { "referrer-policy": "no-referrer" },
        );
    }

    if (grant.role === "device") {
        const name = grant.name ?? "your account";
        const current = auth.user(request);
        const switching =
            current !== undefined && current.id !== grant.targetId
                ? `<p>This browser is signed in as ${escapeHtml(current.name)}. It will change to ${escapeHtml(name)}.</p>`
                : "";

        return send(
            response,
            200,
            page(
                `Sign in as ${name} · Pi Pocket`,
                `<h1>Sign in as ${escapeHtml(name)}</h1><p>This device will sign in as you, ${escapeHtml(name)}. It connects to your existing account.</p>${switching}<form method="post"><button type="submit">Sign in as ${escapeHtml(name)}</button></form>`,
            ),
            "text/html; charset=utf-8",
            { "referrer-policy": "no-referrer" },
        );
    }

    const where =
        grant.session === undefined
            ? "every session on this server"
            : `the session “${escapeHtml(await app.conversationTitle(conversationId(grant.session)))}”`;
    const can =
        grant.role === "viewer"
            ? `read ${where} and chat with the people there, but not steer Pi`
            : `read and steer ${where}. Pi can run commands on this machine`;

    return send(
        response,
        200,
        page(
            "Join Pi Pocket",
            `<h1>Join Pi Pocket</h1><p>This device will be able to ${can}.</p><form method="post"><label>Your name<input name="name" maxlength="40" autofocus required placeholder="e.g. Alex"></label><button type="submit">Join</button></form>`,
        ),
        "text/html; charset=utf-8",
        { "referrer-policy": "no-referrer" },
    );
}

/** `/share`: a share that reached the server, before the service worker that takes shares was installed here. */
export function sharePage(response: ServerResponse): void {
    return send(
        response,
        200,
        page(
            "Share to Pi",
            `<h1>Open Pi Pocket first</h1><p>Sharing works once Pi Pocket has been opened on this device over https. Open it, then share again.</p><p><a href="/">Open Pi Pocket</a></p>`,
        ),
        "text/html; charset=utf-8",
    );
}
