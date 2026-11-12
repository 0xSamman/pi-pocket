import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { cleanUp, openApp, root, scriptedModel, until, type App } from "./helpers.ts";
import { Browsers } from "../src/server/browser.ts";
import { findBrowser } from "../src/server/browser/discovery.ts";
import { VIEWPORTS } from "../src/server/browser/viewport.ts";
import { createHandler } from "../src/server/http.ts";

let app: App;
let server: Server;
let browsers: Browsers;
let base: string;
const real = { skip: findBrowser() === undefined ? "no Chromium" : false };

before(async () => {
    if (real.skip) {
        return;
    }

    app = await openApp(scriptedModel(), join(root, "target-ui-data"));
    server = createServer(
        createHandler({ app, listen: { host: "127.0.0.1", port: 0 }, restart: () => {} }),
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    browsers = new Browsers({
        dataDir: join(root, "target-ui-browser"),
        load: async () => undefined,
        save: () => {},
    });
});

after(async () => {
    await browsers?.closeAll({ final: true });
    server?.closeAllConnections();
    server?.close();
    await app?.close();
    cleanUp();
});

for (const [index, viewport] of [VIEWPORTS.desktop, VIEWPORTS.mobile].entries()) {
    test(
        `Owner invites an existing person on ${index === 0 ? "desktop" : "phone"}`,
        real,
        async () => {
            const issuer = await browsers.open(index * 2 + 1);
            const recipient = await browsers.open(index * 2 + 2);
            const target = app.config.addUser(`Synthetic recipient ${index}`, "viewer", [
                "123",
            ]).user;
            const originalCount = app.config.users.length;

            await issuer.setViewport(viewport);
            await recipient.setViewport(viewport);
            await issuer.navigate(
                `${base}/login?token=${encodeURIComponent(app.config.ownerToken)}`,
            );
            await until(
                async () =>
                    JSON.parse(
                        await issuer.evaluate(
                            `return JSON.stringify((await import('/store.js')).store.state.me?.role === 'owner')`,
                        ),
                    ),
                "owner signed in",
            );
            await issuer.evaluate(
                `(await import('/store.js')).openSheet({type:'people'}); window.confirm = () => true;`,
            );
            await until(
                async () =>
                    JSON.parse(
                        await issuer.evaluate(
                            `return JSON.stringify([...document.querySelectorAll('.person-row')].some(row => row.textContent.includes(${JSON.stringify(target.name)}) && [...row.querySelectorAll('button')].some(b => b.textContent.trim() === 'Sign in a device')))`,
                        ),
                    ),
                "existing person has device action",
            );
            await issuer.evaluate(
                `[...document.querySelectorAll('.person-row')].find(row => row.textContent.includes(${JSON.stringify(target.name)})).querySelector('button').click()`,
            );
            await until(
                async () =>
                    JSON.parse(
                        await issuer.evaluate(
                            `return JSON.stringify(Boolean(document.querySelector('.invite-code-value')))`,
                        ),
                    ),
                "device invitation appears",
            );
            const help = JSON.parse(
                await issuer.evaluate(
                    `return JSON.stringify(document.querySelector('.sheet').textContent)`,
                ),
            ) as string;

            assert.ok(help.includes(target.id));
            assert.ok(help.includes("Verify the recipient"));
            assert.ok(help.includes("Existing devices stay signed in"));
            const code = JSON.parse(
                await issuer.evaluate(
                    `return JSON.stringify(document.querySelector('.invite-code-value').textContent.replace(/\\s/g,''))`,
                ),
            ) as string;

            // A different account with the same name still needs a switching warning.
            const sameName = app.config.addUser(target.name, "guest");

            await recipient.navigate(`${base}/login?token=${encodeURIComponent(sameName.token)}`);
            await until(
                async () =>
                    JSON.parse(
                        await recipient.evaluate(
                            `try { return JSON.stringify((await import('/store.js')).store.state.me?.id === ${JSON.stringify(sameName.user.id)}); } catch { return 'false'; }`,
                        ),
                    ),
                "same-name account signed in independently",
                30_000,
            );
            // Browsers.open gives each conversation a separate browser context and cookie jar.
            await recipient.navigate(`${base}/join/${code}`);
            assert.ok(
                JSON.parse(
                    await recipient.evaluate(`return JSON.stringify(document.body.textContent)`),
                ).includes("This browser is signed in as"),
            );
            assert.ok(
                JSON.parse(
                    await recipient.evaluate(
                        `return JSON.stringify(document.querySelector('h1').textContent)`,
                    ),
                ).includes(target.name),
            );
            await recipient.evaluate(`document.querySelector('form button').click()`);
            await until(
                async () => {
                    try {
                        return JSON.parse(
                            await recipient.evaluate(
                                `return JSON.stringify((await import('/store.js')).store.state.me?.id === ${JSON.stringify(target.id)})`,
                            ),
                        );
                    } catch {
                        return false;
                    }
                },
                "recipient keeps existing identity",
                30_000,
            );
            assert.equal(app.config.users.length, originalCount + 1);
            assert.equal(target.role, "viewer");
            assert.deepEqual(target.sessions, ["123"]);
            assert.equal(
                JSON.parse(
                    await issuer.evaluate(
                        `return JSON.stringify((await import('/store.js')).store.state.me?.role)`,
                    ),
                ),
                "owner",
            );
            await issuer.evaluate(`(await import('/store.js')).closeSheet()`);
        },
    );
}
