// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeyVerify;

/**
 * This key manager produces new instances of {@code JwtRsaSsaPss1Verify}. It doesn't support key
 * generation.
 */
@LowLevelCryptoCaller
final class JwtRsaSsaPssVerifyKeyManager {

  static final PrimitiveConstructor<JwtRsaSsaPssPublicKey, JwtPublicKeyVerify>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtRsaSsaPssPublicKeyVerify::create,
              JwtRsaSsaPssPublicKey.class,
              JwtPublicKeyVerify.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";
  }

  private JwtRsaSsaPssVerifyKeyManager() {}
}
