// Copyright 2026 Google LLC
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

package com.google.crypto.tink.jwt.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import javax.annotation.Nullable;

/** Creates {@link JwtEcdsaPrivateKey} instances. */
public final class JwtEcdsaKeyCreator {

  @AccessesPartialKey
  public static JwtEcdsaPrivateKey createKey(
      JwtEcdsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      throw new GeneralSecurityException(
          "Cannot create JwtEcdsaPrivateKey in FIPS mode without FIPS module");
    }
    KeyPair keyPair =
        EllipticCurves.generateKeyPair(parameters.getAlgorithm().getEcParameterSpec());
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    JwtEcdsaPublicKey.Builder publicKeyBuilder =
        JwtEcdsaPublicKey.builder().setParameters(parameters).setPublicPoint(pubKey.getW());
    if (idRequirement != null) {
      publicKeyBuilder.setIdRequirement(idRequirement);
    }
    return JwtEcdsaPrivateKey.create(
        publicKeyBuilder.build(),
        SecretBigInteger.fromBigInteger(privKey.getS(), InsecureSecretKeyAccess.get()));
  }

  private JwtEcdsaKeyCreator() {}
}
