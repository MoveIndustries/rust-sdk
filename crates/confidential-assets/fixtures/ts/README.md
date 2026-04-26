# TS fixture generator

Produces JSON for `tests/fixtures/transfer_sigma.fixture.json`, consumed by `tests/transfer_sigma_fixture.rs`.

## Layout

From `fixtures/ts`, the Movement SDK is expected at:

`../../../ts-sdk/confidential-assets` (sibling of this repo — see `package.json` `file:` dependency).

## One-time setup

1. Build the TypeScript SDK at `../ts-sdk/confidential-assets` relative to **this** repo’s root (so `dist/` exists):

```bash
cd ../ts-sdk/confidential-assets
pnpm install --no-frozen-lockfile   # if your lockfile is out of date
pnpm build
```

2. From **this** repo root (`confidential-assets-rs`), install fixture dependencies:

```bash
cd fixtures/ts
pnpm install
```

## Generate

Run `tsx` directly so stdout is **only** JSON (`pnpm run` can print extra lines before the `{`):

```bash
cd fixtures/ts
./node_modules/.bin/tsx generate.ts > ../../tests/fixtures/transfer_sigma.fixture.json
```

The fixture is emitted with `"skip": false` and deterministic test keys. Then from the repo root:

```bash
cargo test --test transfer_sigma_fixture
```

## Why not `@aptos-labs/confidential-assets` from npm?

Parity depends on the same **Twisted Ed25519** derivation and **H** point as Movement. Use the Movement `confidential-assets` sources that match this crate (local `file:` link or published `@moveindustries/confidential-assets` once versions align).
