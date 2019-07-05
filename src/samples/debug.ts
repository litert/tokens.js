// tslint:disable: no-console

import * as Tokens from "../lib";

const jwts = Tokens.createJWTEncoder();

jwts.registerHMACProfile("aaaaaa", "sha512", "hello world!");

const test = jwts.create("aaaaaa", {
    "iss": "hello",
    "name": "laoxie"
});

console.log(test);

console.log(JSON.stringify(jwts.verify(test, "aaaaaa"), null, 2));
