/**
 *  Copyright 2020 Angus.Fenying <fenying@litert.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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
