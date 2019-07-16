// tslint:disable: no-console

import * as Tokens from "../lib";

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
