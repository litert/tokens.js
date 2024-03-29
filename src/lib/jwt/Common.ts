/**
 *  Copyright 2021 Angus.Fenying <fenying@litert.org>
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

import * as Signs from '@litert/signatures';

export enum EJWA {
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512'
}

export type TValidHashAlgorithms = 'sha256' | 'sha384' | 'sha512';

export interface IRecurrsiveDict {

    [k: string]: number | string | null | boolean | IRecurrsiveDict;
}

export interface IJWTPayload extends IRecurrsiveDict {

    /**
     * The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    'iss': string;

    /**
     * The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.  The
     * "sub" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    'sub': string;

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-
     * sensitive strings, each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     */
    'aud': string;

    /**
     * The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than
     * a few minutes, to account for clock skew.  Its value MUST be a number
     * containing a NumericDate value.  Use of this claim is OPTIONAL.
     */
    'exp': number;

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.  The processing of the "nbf"
     * claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the "nbf" claim.  Implementers MAY
     * provide for some small leeway, usually no more than a few minutes, to
     * account for clock skew.  Its value MUST be a number containing a
     * NumericDate value.  Use of this claim is OPTIONAL.
     */
    'nbf': number;

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    'iat': number;

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-
     * sensitive string.  Use of this claim is OPTIONAL.
     */
    'jti': number;
}

export interface IJWTHeader {

    [key: string]: string | number;

    /**
     * The signature algorithm used in current JWT.
     */
    'alg': EJWA;

    /**
     * The type of current JWT.
     */
    'typ': 'JWT';
}

export interface IKeyPair {

    'public': Buffer | string;

    'private': Buffer | string | Signs.IAsymmetricKey;
}

export interface IJWT<T extends IJWTPayload = IJWTPayload> {

    /**
     * The header of current JWT.
     */
    'header': IJWTHeader;

    /**
     * The payload of current JWT.
     */
    'payload': T;

    /**
     * The signature of current JWT.
     */
    'signature': {

        /**
         * The value of signature.
         */
        'value': string;

        /**
         * The verification result of signature.
         */
        'verified': boolean;
    };
}

export interface IProfileOptions {

    /**
     * The name of new profile.
     */
    name: string;

    /**
     * The predefined headers of JWT.
     */
    predefinedHeaders?: IRecurrsiveDict;

    /**
     * The predefined payload of JWT.
     */
    predefinedPayload?: Partial<IJWTPayload>;

    /**
     * The name of hash algorithm to be used in new profile.
     */
    algorithm: TValidHashAlgorithms;
}

export interface IHMACProfileOptions extends IProfileOptions {

    /**
     * The key of HMAC signature algorithm to be used in new profile.
     */
    key: string | Buffer;
}

export interface IECDSAProfileOptions extends IProfileOptions {

    /**
     * The key of ECDSA signature algorithm to be used in new profile.
     */
    key: IKeyPair;
}

export interface IRSAProfileOptions extends IProfileOptions {

    /**
     * The key of RSA signature algorithm to be used in new profile.
     */
    key: IKeyPair;

    /**
     * Set to true to use PSS-MGF1 padding. [default: false]
     *
     * > For JWA `PS256`, `PS384`, and `PS512`.
     */
    pssmgf1Padding?: boolean;
}

export interface IJWTEncoder {

    /**
     * Remove specific profile by name.
     *
     * @param name The name of profile to be removed.
     */
    removeProfile(name: string): this;

    /**
     * Register a profile of HMAC algorithm.
     */
    registerHMACProfile(opts: IHMACProfileOptions): this;

    /**
     * Register a profile of ECDSA algorithm.
     *
     * @param profileName   The name of new profile.
     * @param algorithm     The name of hash algorithm to be used in new profile.
     * @param key           The key pair of hash algorithm to be used in new profile.
     * @param predefinedHeaders The predefined headers of JWT
     */
    registerECDSAProfile(opts: IECDSAProfileOptions): this;

    /**
     * Register a profile of RSA algorithm.
     *
     * @param profileName       The name of new profile.
     * @param algorithm         The name of hash algorithm to be used in new profile.
     * @param key               The key pair of hash algorithm to be used in new profile.
     * @param pssmgf1Padding    Set to true to use PSS-MGF1 padding. [default: false]
     * @param predefinedHeaders The predefined headers of JWT
     */
    registerRSAProfile(opts: IRSAProfileOptions): this;

    /**
     * Create a JWT.
     *
     * @param profile   The name of profile to be used.
     * @param payload   The payload of new JWT.
     */
    create(
        profile: string,
        payload: Partial<IJWTPayload>,
        headers?: IRecurrsiveDict
    ): string;

    /**
     * Decode and verify a JWT.
     *
     * @param jwt       The JWT to be decoded and verified.
     * @param profile   The name of profile to be used. If no specified, all profiles will be tried.
     */
    verify(
        jwt: string,
        profile?: string
    ): IJWT;
}
