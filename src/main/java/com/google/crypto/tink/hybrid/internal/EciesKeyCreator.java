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

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import javax.annotation.Nullable;

/** Creates ECIES keys. */
public final class EciesKeyCreator {

  private static ECParameterSpec toParameterSpec(EciesParameters.CurveType curveType)
      throws GeneralSecurityException {
    if (curveType == EciesParameters.CurveType.NIST_P256) {
      return EllipticCurvesUtil.NIST_P256_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P384) {
      return EllipticCurvesUtil.NIST_P384_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P521) {
      return EllipticCurvesUtil.NIST_P521_PARAMS;
    }
    throw new GeneralSecurityException("Unsupported curve type: " + curveType);
  }

  @AccessesPartialKey
  public static EciesPrivateKey createKey(
      EciesParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    // toParameterSpec throws for curve X25519
    KeyPair keyPair = EllipticCurves.generateKeyPair(toParameterSpec(parameters.getCurveType()));
    ECPublicKey ecPubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey ecPrivKey = (ECPrivateKey) keyPair.getPrivate();

    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, ecPubKey.getW(), idRequirement);
    return EciesPrivateKey.createForNistCurve(
        publicKey,
        SecretBigInteger.fromBigInteger(ecPrivKey.getS(), InsecureSecretKeyAccess.get()));
  }

  private EciesKeyCreator() {}
}
