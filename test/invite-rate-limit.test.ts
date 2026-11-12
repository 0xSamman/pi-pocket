import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join as joinPath } from "node:path";
import { test } from "node:test";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { PocketApp } from "../src/server/app.ts";
import { Auth } from "../src/server/auth.ts";
import { ConfigStore } from "../src/server/config.ts";
import { join, login } from "../src/server/http/sign-in.ts";
import { createHandler } from "../src/server/http.ts";
import { cleanUp, openApp, scriptedModel } from "./helpers.ts";

const app = {} as PocketApp;
let lookups = 0;
const auth = {
    validInviteProof: () => false,
    invite: () => {
        lookups++;

        return undefined;
    },
    redeem: () => {
        lookups++;

        return undefined;
    },
} as unknown as Auth;

async function attempt(
    address: string,
    method = "GET",
    forwarded = "",
    code = "invalid",
    useAuth = auth,
    proof?: string,
) {
    const request = Object.assign(Readable.from(method === "POST" ? [Buffer.from("name=A")] : []), {
        method,
        url: proof === undefined ? "/" : `/?proof=${proof}`,
        headers: { "x-forwarded-for": forwarded, "sec-fetch-site": "same-origin" },
        socket: { remoteAddress: address },
    }) as unknown as IncomingMessage;
    let status = 0;
    let headers: Record<string, string> = {};
    const response = {
        req: request,
        setHeader: () => {},
        writeHead: (value: number, fields: Record<string, string>) => {
            status = value;
            headers = fields;
        },
        end: () => {},
    } as unknown as ServerResponse;

    await join(app, useAuth, request, response, code);

    return { status, headers };
}

test("invite preview and redemption share a bounded per-socket window", async (t) => {
    let now = 1_000_000;

    t.mock.method(Date, "now", () => now);
    lookups = 0;

    for (let i = 0; i < 30; i++) {
        assert.equal((await attempt("192.0.2.1", i % 2 ? "POST" : "GET", String(i))).status, 410);
    }

    const blocked = await attempt("192.0.2.1", "POST", "other");

    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers["retry-after"], "600");
    assert.equal(lookups, 45);
    assert.equal((await attempt("192.0.2.1", "GET", "", "another-code")).status, 410);
    assert.equal((await attempt("192.0.2.2")).status, 410);
    now += 600_000;
    assert.equal((await attempt("192.0.2.1")).status, 410);
});

test("a shared socket has a generous total limit even for distinct codes", async (t) => {
    let now = 5_000_000;

    t.mock.method(Date, "now", () => now);

    for (let i = 0; i < 3000; i++) {
        assert.equal((await attempt("proxy", "GET", "", `guess-${i}`)).status, 410);
    }

    assert.equal((await attempt("proxy", "GET", "", "invalid-overflow")).status, 429);
    const dir = mkdtempSync(joinPath(tmpdir(), "invite-proof-"));

    try {
        const config = new ConfigStore(dir);
        const realAuth = new Auth(config);
        const owner = config.userByToken(config.ownerToken)!;
        const invite = realAuth.createInvite(owner, { role: "owner" });
        let checks = 0;
        const tracked = {
            validInviteProof: realAuth.validInviteProof.bind(realAuth),
            invite: (code: string) => {
                checks++;

                return realAuth.invite(code);
            },
            user: realAuth.user.bind(realAuth),
            redeem: realAuth.redeem.bind(realAuth),
        } as unknown as Auth;

        assert.equal(new Auth(config).validInviteProof(invite.code, invite.proof), true);
        assert.equal(
            (await attempt("proxy", "GET", "", invite.code, tracked, "0".repeat(64))).status,
            429,
        );
        assert.equal(checks, 0);
        assert.equal(
            (await attempt("proxy", "GET", "", invite.code, tracked, invite.proof)).status,
            200,
        );
        assert.equal(
            (await attempt("proxy", "POST", "", invite.code, tracked, invite.proof)).status,
            303,
        );
        assert.equal(checks, 2);
        config.rotateOwnerToken();
        assert.equal(realAuth.validInviteProof(invite.code, invite.proof), false);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }

    now += 600_000;
    assert.equal((await attempt("proxy", "GET", "", "legitimate")).status, 410);
});

test("proved buckets survive rejected discovery and unsigned table churn", async (t) => {
    let now = 7_000_000;
    let lookups = 0;
    const tracked = {
        validInviteProof: (code: string, proof: string | null) =>
            code === "protected" && proof === "proof",
        invite: (code: string) => {
            lookups++;

            return code === "protected" ? { role: "owner" } : undefined;
        },
        user: () => undefined,
    } as unknown as Auth;

    t.mock.method(Date, "now", () => now);

    for (let i = 0; i < 29; i++) {
        assert.equal((await attempt("shared", "GET", "", "protected", tracked)).status, 200);
    }

    assert.equal((await attempt("shared", "GET", "", "protected", tracked, "proof")).status, 200);
    assert.equal((await attempt("shared", "GET", "", "protected", tracked)).status, 429);
    assert.equal((await attempt("shared", "GET", "", "protected", tracked, "proof")).status, 429);

    for (let i = 0; i < 2970; i++) {
        assert.equal((await attempt("shared", "GET", "", `discovery-${i}`, tracked)).status, 410);
    }

    const before = lookups;

    for (let i = 0; i < 4100; i++) {
        assert.equal((await attempt("shared", "GET", "", `rejected-${i}`, tracked)).status, 429);
    }

    assert.equal(lookups, before);

    for (let i = 0; i < 4100; i++) {
        assert.equal(
            (await attempt(`other-${Math.floor(i / 2500)}`, "GET", "", `churn-${i}`, tracked))
                .status,
            410,
        );
    }

    assert.equal((await attempt("shared", "GET", "", "protected", tracked, "proof")).status, 429);
    now += 600_000;
    assert.equal((await attempt("shared", "GET", "", "protected", tracked, "proof")).status, 200);
});

test("spent proofs allocate no buckets and live proofs share a global code limit", async (t) => {
    const now = 8_300_000;
    const tracked = {
        validInviteProof: (_code: string, proof: string | null) => proof === "proof",
        invite: (code: string) => (code === "live" ? { role: "owner" } : undefined),
        user: () => undefined,
    } as unknown as Auth;

    t.mock.method(Date, "now", () => now);

    for (let i = 0; i < 4100; i++) {
        assert.equal(
            (await attempt(`stale-${i}`, "GET", "", "spent", tracked, "proof")).status,
            410,
        );
    }

    for (let i = 0; i < 30; i++) {
        assert.equal((await attempt(`live-${i}`, "GET", "", "live", tracked, "proof")).status, 200);
    }

    assert.equal((await attempt("live-overflow", "GET", "", "live", tracked, "proof")).status, 429);
});

test("proved bucket capacity fails closed without evicting active counts", async (t) => {
    let now = 9_000_000;
    const tracked = {
        validInviteProof: (_code: string, proof: string | null) => proof === "proof",
        invite: () => ({ role: "owner" }),
        user: () => undefined,
    } as unknown as Auth;

    t.mock.method(Date, "now", () => now);

    for (let i = 0; i < 4096; i++) {
        assert.equal(
            (await attempt("capacity", "GET", "", `proved-${i}`, tracked, "proof")).status,
            200,
        );
    }

    assert.equal((await attempt("capacity", "GET", "", "overflow", tracked, "proof")).status, 429);

    for (let i = 0; i < 29; i++) {
        assert.equal(
            (await attempt("capacity", "GET", "", "proved-0", tracked, "proof")).status,
            200,
        );
    }

    assert.equal((await attempt("capacity", "GET", "", "proved-0", tracked, "proof")).status, 429);
    now += 600_000;
    assert.equal((await attempt("capacity", "GET", "", "overflow", tracked, "proof")).status, 200);
});

test("address table fails closed at capacity and recovers after expiry", async (t) => {
    let now = 10_000_000;

    t.mock.method(Date, "now", () => now);

    for (let i = 0; i < 4096; i++) {
        assert.equal((await attempt(`peer-${i}`)).status, 410);
    }

    assert.equal((await attempt("overflow")).status, 429);
    now += 600_000;
    assert.equal((await attempt("overflow")).status, 410);
});

test("device redemption preserves the target tunnel while new guests get the tunnel", async () => {
    for (const role of ["device", "guest"] as const) {
        const updates: unknown[] = [];
        const target = { id: "target", role: "guest", tunnel: "old.example" };
        const fakeApp = {
            config: { updateUser: (...args: unknown[]) => updates.push(args) },
        } as unknown as PocketApp;
        const fakeAuth = {
            validInviteProof: () => false,
            invite: () => ({ role }),
            redeem: () => ({ user: target, token: "synthetic" }),
        } as unknown as Auth;
        const request = Object.assign(Readable.from([Buffer.from("name=A")]), {
            method: "POST",
            headers: { host: "new.trycloudflare.com", "sec-fetch-site": "same-origin" },
            socket: { remoteAddress: `tunnel-${role}` },
        }) as unknown as IncomingMessage;
        let status = 0;
        let cookie = "";
        const response = {
            req: request,
            setHeader: (_name: string, value: string) => {
                cookie = value;
            },
            writeHead: (value: number) => {
                status = value;
            },
            end: () => {},
        } as unknown as ServerResponse;

        await join(fakeApp, fakeAuth, request, response, "synthetic");
        assert.equal(status, 303);
        assert.match(cookie, /HttpOnly; SameSite=Lax/);
        assert.deepEqual(
            updates,
            role === "device" ? [] : [["target", { tunnel: "new.trycloudflare.com" }]],
        );
    }
});

test("login and join POST require Origin or Fetch Metadata", async () => {
    const cases: Array<[Record<string, string>, boolean]> = [
        [{ origin: "http://evil.example" }, false],
        [{ origin: "null" }, false],
        [{ origin: "null", "sec-fetch-site": "same-origin" }, true],
        [{ origin: "null", "sec-fetch-site": "cross-site" }, false],
        [{ origin: "null", "sec-fetch-site": "same-site" }, false],
        [{ origin: "null", "sec-fetch-site": "none" }, false],
        [{ origin: "http://good.example/path" }, false],
        [{ origin: "http://good.example", "sec-fetch-site": "cross-site" }, false],
        [{ origin: "http://evil.example", "sec-fetch-site": "same-origin" }, false],
        [{ origin: "http://good.example" }, true],
        [
            {
                origin: "https://public.example",
                "x-forwarded-host": "public.example",
                "x-forwarded-proto": "https",
            },
            true,
        ],
        [{ "sec-fetch-site": "same-origin" }, true],
        [{}, false],
    ];

    for (const route of ["login", "join"] as const) {
        for (const [headers, allowed] of cases) {
            const request = Object.assign(Readable.from([Buffer.from("name=A")]), {
                method: "POST",
                headers: { host: "good.example", ...headers },
                socket: { remoteAddress: `csrf-${route}` },
            }) as unknown as IncomingMessage;
            const response = {
                req: request,
                writeHead: () => {},
                end: () => {},
            } as unknown as ServerResponse;
            const run = () =>
                route === "join"
                    ? join(app, auth, request, response, "invalid")
                    : login(
                          { tokenUser: () => undefined } as unknown as Auth,
                          request,
                          response,
                          new URL("http://good.example/login"),
                      );

            if (allowed) {
                await run();
            } else {
                await assert.rejects(
                    run,
                    (error: unknown) => (error as { status?: number }).status === 403,
                );
            }
        }
    }
});

test("invite API signs its main and alternate links", async () => {
    const app = await openApp(scriptedModel());
    const server = createServer(
        createHandler({ app, listen: { host: "0.0.0.0", port: 0 }, restart: () => {} }),
    );

    try {
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        const port = (server.address() as { port: number }).port;
        const response = await fetch(`http://127.0.0.1:${port}/api/invite`, {
            method: "POST",
            headers: {
                authorization: `Bearer ${app.config.ownerToken}`,
                "x-pocket": "1",
                "content-type": "application/json",
            },
            body: "{}",
        });

        assert.equal(response.status, 200);
        const result = (await response.json()) as {
            code: string;
            proof: string;
            url: string;
            alternatives: string[];
        };
        const verifier = new Auth(app.config);

        assert.equal(verifier.validInviteProof(result.code, result.proof), true);

        for (const link of [result.url, ...result.alternatives]) {
            const parsed = new URL(link);

            assert.equal(parsed.pathname.endsWith(`/${result.code}`), true);
            assert.equal(
                verifier.validInviteProof(result.code, parsed.searchParams.get("proof")),
                true,
            );
        }
    } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await app.close();
        cleanUp();
    }
});
