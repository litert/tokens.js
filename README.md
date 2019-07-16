# LiteRT/Tokens

[![Strict TypeScript Checked](https://badgen.net/badge/TS/Strict "Strict TypeScript Checked")](https://www.typescriptlang.org)
[![npm version](https://img.shields.io/npm/v/@litert/tokens.svg?colorB=brightgreen)](https://www.npmjs.com/package/@litert/tokens "Stable Version")
[![License](https://img.shields.io/npm/l/@litert/tokens.svg?maxAge=2592000?style=plastic)](https://github.com/litert/tokens/blob/master/LICENSE)
[![node](https://img.shields.io/node/v/@litert/tokens.svg?colorB=brightgreen)](https://nodejs.org/dist/latest-v8.x/)
[![GitHub issues](https://img.shields.io/github/issues/litert/tokens.js.svg)](https://github.com/litert/tokens.js/issues)
[![GitHub Releases](https://img.shields.io/github/release/litert/tokens.js.svg)](https://github.com/litert/tokens.js/releases "Stable Release")

A token serialization & unserialization library.

## Requirement

- TypeScript v3.1.x (or newer)
- Node.js v8.0.0 (or newer)

## Installation

```sh
npm i @litert/tokens --save
```

## Usage

```ts
import * as Tokens from "@litert/tokens";

// Create a JWT encoder.
const jwts = Tokens.createJWTEncoder();

// Register a profile with HMAC-SHA-512 algorithm.
jwts.registerHMACProfile("test-hs512", "sha512", "hello world!");

// Create a JWT with hs512 profile.
const testJWT = jwts.create("test-hs512", {
    "iss": "Heaven",
    "name": "Hik"
});

// Print the JWT string.
console.log(testJWT);

// Try to verify it, if verified successfully, check the testInfo.signature.
const testInfo = jwts.verify(testJWT, "test-hs512");

if (testInfo.signature.verified) {

    console.info("Success!");
}
else {

    console.error("Failed!");
}

// Print the JWT structure.
console.log(JSON.stringify(testInfo, null, 2));
```

## Document

Preparing yet.

## License

This library is published under [Apache-2.0](./LICENSE) license.
