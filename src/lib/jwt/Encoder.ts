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
import * as Enc from '@litert/encodings';

import * as C from './Common';
import * as E from '../Errors';

interface IProfile {

    jwa: C.EJWA;

    name: string;

    signer: Signs.ISigner<'base64url'>;

    predefinedHeaders: C.IRecurrsiveDict;

    predefinedPayload: Partial<C.IJWTPayload>;
}

class JWTEncoder implements C.IJWTEncoder {

    private _profiles: Record<string, IProfile> = {};

    public registerHMACProfile(opts: C.IHMACProfileOptions): this {

        if (this._profiles[opts.name]) {

            throw new E.E_DUP_PROFILE({ profileName: opts.name });
        }

        this._profiles[opts.name] = {

            'jwa': (C.EJWA as any)['HS' + opts.algorithm.substr(3)],
            'name': opts.name,
            'signer': Signs.HMAC.createSigner(
                opts.algorithm,
                opts.key,
                'base64url'
            ),
            'predefinedHeaders': opts.predefinedHeaders ?? {},
            'predefinedPayload': opts.predefinedPayload ?? {}
        };

        return this;
    }

    public registerRSAProfile(opts: C.IRSAProfileOptions): this {

        if (this._profiles[opts.name]) {

            throw new E.E_DUP_PROFILE({ profileName: opts.name });
        }

        this._profiles[opts.name] = {

            'jwa': (C.EJWA as any)[(opts.pssmgf1Padding ? 'PS' : 'RS') + opts.algorithm.substr(3)],
            'name': opts.name,
            'signer': Signs.RSA.createSigner(
                opts.algorithm,
                opts.key.public,
                opts.key.private,
                opts.pssmgf1Padding ? Signs.ERSAPadding.PSS_MGF1 : Signs.ERSAPadding.PKCS1_V1_5,
                'base64url'
            ),
            'predefinedHeaders': opts.predefinedHeaders ?? {},
            'predefinedPayload': opts.predefinedPayload ?? {}
        };

        return this;
    }

    public registerECDSAProfile(opts: C.IECDSAProfileOptions): this {

        if (this._profiles[opts.name]) {

            throw new E.E_DUP_PROFILE({ profileName: opts.name });
        }

        this._profiles[opts.name] = {

            'jwa': (C.EJWA as any)['ES' + opts.algorithm.substr(3)],
            'name': opts.name,
            'signer': Signs.ECDSA.createSigner(
                opts.algorithm,
                opts.key.public,
                opts.key.private,
                Signs.EECDSAFormat.IEEE_P1363,
                'base64url'
            ),
            'predefinedHeaders': opts.predefinedHeaders ?? {},
            'predefinedPayload': opts.predefinedPayload ?? {}
        };

        return this;
    }

    public removeProfile(name: string): this {

        delete this._profiles[name];

        return this;
    }

    public create(profileName: string, payload: C.IJWTPayload, headers?: C.IRecurrsiveDict): string {

        const profile = this._profiles[profileName];

        if (!profile) {

            throw new E.E_PROFILE_NOT_FOUND({ metadata: { profileName} });
        }

        const body = Enc.stringToBase64Url(JSON.stringify({
            'typ': 'JWT',
            'alg': C.EJWA[profile.jwa],
            ...profile.predefinedHeaders,
            ...headers
        })) + '.' + Enc.stringToBase64Url(JSON.stringify({
            ...profile.predefinedPayload,
            ...payload
        }));

        return `${body}.${profile.signer.sign(body)}`;
    }

    private _tryVerify(algo: string, body: string, signature: string, profileName: string): boolean {

        const profile = this._profiles[profileName];

        if (!profile) {

            throw new E.E_PROFILE_NOT_FOUND({ metadata: { profileName} });
        }

        return C.EJWA[profile.jwa] === algo && profile.signer.verify(
            body,
            signature
        );
    }

    public verify(jwt: string, profileName?: string): C.IJWT {

        const segs = jwt.split('.');

        if (segs.length !== 3) {

            throw new E.E_MALFORMED_JWT();
        }

        let header!: { 'typ': string; 'alg': string; };

        let payload!: C.IJWTPayload;

        try {

            header = JSON.parse(Enc.stringFromBase64Url(segs[0]));

            payload = JSON.parse(Enc.stringFromBase64Url(segs[1]));

        }
        catch (e) {

            throw new E.E_MALFORMED_JWT({ metadata: { origin: e } });
        }

        if (typeof header !== 'object' || header.typ !== 'JWT' || typeof header.alg !== 'string') {

            throw new E.E_MALFORMED_JWT();
        }

        const body = `${segs[0]}.${segs[1]}`;

        let verified = false;

        if (profileName) {

            verified = this._tryVerify(header.alg, body, segs[2], profileName);
        }
        else {

            for (let k in this._profiles) {

                if (this._tryVerify(header.alg, body, segs[2], k)) {

                    verified = true;
                    break;
                }
            }
        }

        return {
            header: {
                ...header,
                alg: C.EJWA[header.alg as any] as any,
            } as any,
            payload,
            signature: {
                value: segs[2],
                verified
            }
        };
    }
}

export function createJWTEncoder(): C.IJWTEncoder {

    return new JWTEncoder();
}
