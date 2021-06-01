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

import * as $Exceptions from '@litert/exception';

export const exceptionRegistry = $Exceptions.createExceptionRegistry({
    module: 'tokens.litert.org',
    types: {
        'public': {
            index: $Exceptions.createIncreaseCodeIndex(0)
        }
    }
});

export const E_DUP_PROFILE = exceptionRegistry.register({
    name: 'dup_profile',
    message: 'The name of profile already exists.',
    type: 'public',
    metadata: {}
});

export const E_PROFILE_NOT_FOUND = exceptionRegistry.register({
    name: 'profile_not_found',
    message: 'The name of profile doesn\'t exist.',
    type: 'public',
    metadata: {}
});

export const E_MALFORMED_JWT = exceptionRegistry.register({
    name: 'malformed_jwt',
    message: 'The jwt to be decoded is malformed.',
    type: 'public',
    metadata: {}
});
