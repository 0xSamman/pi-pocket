import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Auth, type InviteGrant } from "../src/server/auth.ts";
import { ConfigStore } from "../src/server/config.ts";

function fixture() {
    const dir = mkdtempSync(join(tmpdir(), "pocket-pair-"));
    const config = new ConfigStore(dir);
    const owner = config.userByToken(config.ownerToken)!;
    const target = config.addUser("Target", "viewer", ["123"]);
    const guest = config.addUser("Guest", "guest");

    return { dir, config, owner, target, guest, auth: new Auth(config) };
}

test("owner targets an existing account and scoped viewers can pair themselves", () => {
    const f = fixture();

    try {
        assert.throws(
            () => f.auth.createInvite(f.guest.user, { role: "device", targetId: f.target.user.id }),
            { status: 403 },
        );
        const invite = f.auth.createInvite(
            f.owner,
            { role: "device", targetId: f.target.user.id },
            60,
        );

        assert.equal(invite.minutes, 15);
        const result = f.auth.redeem(invite.code, "ignored")!;

        assert.equal(result.user.id, f.target.user.id);
        assert.deepEqual(result.user.sessions, ["123"]);
        assert.equal(f.auth.tokenUser(result.token)?.id, f.target.user.id);
        assert.equal(f.auth.tokenUser(f.target.token)?.id, f.target.user.id);
        assert.equal(f.auth.redeem(invite.code, ""), undefined);
        const self = f.auth.createInvite(f.target.user, { role: "device" });

        assert.equal(f.auth.redeem(self.code, "")?.user.id, f.target.user.id);
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("revocation, expiry and access changes cannot be reversed", () => {
    const f = fixture();

    try {
        const make = () =>
            f.auth.createInvite(f.owner, { role: "device", targetId: f.target.user.id });
        const cancelled = make();

        f.auth.cancelInvite(cancelled.code, f.owner);
        assert.equal(f.auth.redeem(cancelled.code, ""), undefined);
        const expired = make();

        f.config.invite(expired.code)!.expiresAt = Date.now() - 1;
        assert.equal(f.auth.redeem(expired.code, ""), undefined);
        const changed = make();

        f.config.updateUser(f.target.user.id, { role: "guest" });
        f.config.updateUser(f.target.user.id, { role: "viewer" });
        assert.equal(f.auth.redeem(changed.code, ""), undefined);
        const removed = make();

        f.config.removeUser(f.target.user.id);
        assert.equal(f.auth.redeem(removed.code, ""), undefined);
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("capacity rejects new devices without evicting existing tokens", () => {
    const f = fixture();

    try {
        const pending = f.auth.createInvite(f.owner, {
            role: "device",
            targetId: f.target.user.id,
        });
        const tokens = Array.from({ length: 10 }, (_, i) => `synthetic-${i}`);

        for (const token of tokens) {
            assert.equal(f.config.addUserToken(f.target.user.id, token), true);
        }

        assert.throws(
            () => f.auth.createInvite(f.owner, { role: "device", targetId: f.target.user.id }),
            { status: 409 },
        );
        assert.equal(f.auth.redeem(pending.code, ""), undefined);

        for (const token of [f.target.token, ...tokens]) {
            assert.equal(f.auth.tokenUser(token)?.id, f.target.user.id);
        }
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("owner and device invitations share a persisted issuance limit", () => {
    const f = fixture();

    try {
        for (let i = 0; i < 5; i++) {
            f.auth.createInvite(
                f.owner,
                i % 2 ? { role: "owner" } : { role: "device", targetId: f.target.user.id },
            );
        }

        const config = new ConfigStore(f.dir);

        assert.throws(
            () => new Auth(config).createInvite(config.userById(f.owner.id)!, { role: "owner" }),
            { status: 429 },
        );
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("snapshot-less device invitations are rejected", () => {
    const f = fixture();

    try {
        f.config.addInvite("synthetic-code", {
            role: "device",
            createdBy: f.owner.id,
            targetId: f.target.user.id,
            expiresAt: Date.now() + 60000,
        });
        assert.equal(f.auth.invite("synthetic-code"), undefined);
        assert.equal(f.auth.redeem("synthetic-code", ""), undefined);
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("access guard revokes owner and device grants and blocks issuance until it settles", async () => {
    const f = fixture();

    try {
        const ownerLink = f.auth.createInvite(f.owner, { role: "owner" });
        const deviceLink = f.auth.createInvite(f.owner, {
            role: "device",
            targetId: f.target.user.id,
        });
        let release!: () => void;
        const pending = f.config.withDeviceAccessChange(
            () =>
                new Promise<void>((resolve) => {
                    release = resolve;
                }),
        );

        assert.equal(f.auth.redeem(ownerLink.code, ""), undefined);
        assert.equal(f.auth.redeem(deviceLink.code, ""), undefined);
        assert.throws(() => f.auth.createInvite(f.owner, { role: "owner" }), { status: 403 });
        assert.throws(() => f.auth.createInvite(f.target.user, { role: "device" }), {
            status: 403,
        });
        release();
        await pending;
        const next = f.auth.createInvite(f.owner, { role: "owner" });

        assert.equal(f.auth.redeem(next.code, "")?.token, f.config.ownerToken);
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("snapshot-less owner grants are rejected", () => {
    const f = fixture();

    try {
        f.config.addInvite("synthetic-owner", {
            role: "owner",
            createdBy: f.owner.id,
            expiresAt: Date.now() + 60000,
        });
        assert.equal(f.auth.redeem("synthetic-owner", ""), undefined);
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});

test("restricted owners cannot target another account and mixed owner grants are refused", () => {
    const f = fixture();

    try {
        for (const extra of [
            { session: "123" },
            { targetId: f.target.user.id },
            { team: "x" },
            { admin: true },
        ]) {
            assert.throws(
                () =>
                    f.auth.createInvite(f.owner, {
                        role: "owner",
                        ...extra,
                    } as unknown as InviteGrant),
                {
                    status: 400,
                },
            );
        }

        f.owner.sessions = ["123"];
        f.config.save();
        assert.throws(
            () => f.auth.createInvite(f.owner, { role: "device", targetId: f.target.user.id }),
            { status: 403 },
        );
        assert.ok(f.auth.createInvite(f.owner, { role: "device" }));
    } finally {
        rmSync(f.dir, { recursive: true, force: true });
    }
});
