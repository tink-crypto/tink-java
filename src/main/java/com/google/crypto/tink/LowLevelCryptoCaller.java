// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package com.google.crypto.tink;

import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.LOCAL_VARIABLE;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Required to call methods and classes that create primitives from single keys and without
 * configurations instead of from keysets and with configurations.
 *
 * <p>Methods that require this annotation have the following disadvantages over the usual Tink
 * methods:
 *
 * <ul>
 *   <li>The method may not check that the parameters used satisfy any security requirements. For
 *       example, a method producing a <code>Mac</code> object from a <code>HmacKey</code> might
 *       allow a key size of 4 bytes or a tag size of 4 bytes. This is because these methods often
 *       need to tolerate compatibility with legacy systems, or are used for legacy reasons.
 *   <li>Since the user does not have a keyset, their code depends on a specific key type and on a
 *       single key. Hence, key rotation is more difficult.
 * </ul>
 *
 * <p>Still, such APIs are correct to use in a context where one implements low level cryptography,
 * and the choice of algorithm and the key rotation happens on a higher level, for example, if
 * one implements a protocol which uses various cryptographic algorithms internally.
 */
@Target({TYPE, METHOD, CONSTRUCTOR, FIELD, LOCAL_VARIABLE})
@Retention(RetentionPolicy.CLASS)
public @interface LowLevelCryptoCaller {}
