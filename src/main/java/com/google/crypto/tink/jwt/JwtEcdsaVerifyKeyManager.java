// Copyright 2017 Google LLC
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
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeyVerify;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Enums;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code JwtEcdsaVerify}. It doesn't support key
 * generation.
 */
@LowLevelCryptoCaller
class JwtEcdsaVerifyKeyManager {
  static final PrimitiveConstructor<JwtEcdsaPublicKey, JwtPublicKeyVerify> PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(
          JwtEcdsaPublicKeyVerify::create, JwtEcdsaPublicKey.class, JwtPublicKeyVerify.class);

  static final EllipticCurves.CurveType getCurve(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ES256:
        return EllipticCurves.CurveType.NIST_P256;
      case ES384:
        return EllipticCurves.CurveType.NIST_P384;
      case ES512:
        return EllipticCurves.CurveType.NIST_P521;
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithm.name());
    }
  }

  public static Enums.HashType hashForEcdsaAlgorithm(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ES256:
        return Enums.HashType.SHA256;
      case ES384:
        return Enums.HashType.SHA384;
      case ES512:
        return Enums.HashType.SHA512;
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithm.name());
    }
  }

  static final void validateEcdsaAlgorithm(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    // Purposely ignore the result. This function will throw if the algorithm is invalid.
    Object unused = hashForEcdsaAlgorithm(algorithm);
  }

  private JwtEcdsaVerifyKeyManager() {}

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  }
}
