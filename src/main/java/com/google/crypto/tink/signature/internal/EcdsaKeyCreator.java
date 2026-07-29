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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import javax.annotation.Nullable;

/** Creates ECDSA keys. */
public final class EcdsaKeyCreator {

  @AccessesPartialKey
  public static EcdsaPrivateKey createKey(
      EcdsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    KeyPair keyPair = EllipticCurves.generateKeyPair(parameters.getCurveType().toParameterSpec());
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .setPublicPoint(pubKey.getW())
            .build();

    return EcdsaPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrivateValue(
            SecretBigInteger.fromBigInteger(privKey.getS(), InsecureSecretKeyAccess.get()))
        .build();
  }

  private EcdsaKeyCreator() {}
}
