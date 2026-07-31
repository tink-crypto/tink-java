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
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.CompositeMlDsaVerifyConscrypt.RawKeySpec;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.Arrays;
import javax.annotation.Nullable;

/** Creates {@link CompositeMlDsaPrivateKey} keys using Conscrypt. */
public final class CompositeMlDsaKeyCreator {

  private static final String MLDSA44_ED25519_SHA512_ALGORITHM = "MLDSA44-Ed25519-SHA512";
  private static final String MLDSA65_ED25519_SHA512_ALGORITHM = "MLDSA65-Ed25519-SHA512";

  @AccessesPartialKey
  public static CompositeMlDsaPrivateKey createKey(
      CompositeMlDsaParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      throw new GeneralSecurityException("Composite ML-DSA is not supported in this environment.");
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    if (parameters.getVariant() != CompositeMlDsaParameters.Variant.NO_PREFIX
        && idRequirement == null) {
      throw new GeneralSecurityException("ID requirement must be set for non-NO_PREFIX variants");
    }
    if (parameters.getVariant() == CompositeMlDsaParameters.Variant.NO_PREFIX
        && idRequirement != null) {
      throw new GeneralSecurityException("ID requirement must not be set for NO_PREFIX variant");
    }
    if (parameters.getClassicalAlgorithm() != ClassicalAlgorithm.ED25519) {
      throw new GeneralSecurityException(
          "Only Ed25519 is supported for composite signatures at this time");
    }

    KeyPairGenerator keyPairGenerator;
    KeyFactory keyFactory;
    MlDsaParameters.MlDsaInstance innerMlDsaInstance;
    int mlDsaPubSize;
    if (parameters.getMlDsaInstance() == MlDsaInstance.ML_DSA_44) {
      keyPairGenerator = KeyPairGenerator.getInstance(MLDSA44_ED25519_SHA512_ALGORITHM, provider);
      keyFactory = KeyFactory.getInstance(MLDSA44_ED25519_SHA512_ALGORITHM, provider);
      innerMlDsaInstance = MlDsaParameters.MlDsaInstance.ML_DSA_44;
      mlDsaPubSize = 1312;
    } else if (parameters.getMlDsaInstance() == MlDsaInstance.ML_DSA_65) {
      keyPairGenerator = KeyPairGenerator.getInstance(MLDSA65_ED25519_SHA512_ALGORITHM, provider);
      keyFactory = KeyFactory.getInstance(MLDSA65_ED25519_SHA512_ALGORITHM, provider);
      innerMlDsaInstance = MlDsaParameters.MlDsaInstance.ML_DSA_65;
      mlDsaPubSize = 1952;
    } else {
      throw new GeneralSecurityException("Unsupported ML-DSA instance");
    }

    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    RawKeySpec pubKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
    byte[] rawPkBytes = pubKeySpec.getEncoded();
    RawKeySpec privKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
    byte[] rawSkBytes = privKeySpec.getEncoded();

    byte[] mlDsaPubBytes = Arrays.copyOf(rawPkBytes, mlDsaPubSize);
    byte[] tradPubBytes = Arrays.copyOfRange(rawPkBytes, mlDsaPubSize, rawPkBytes.length);

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(innerMlDsaInstance, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(Bytes.copyFrom(mlDsaPubBytes))
            .build();
    Ed25519PublicKey edPublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, Bytes.copyFrom(tradPubBytes), null);

    byte[] mlDsaSeedBytes = Arrays.copyOf(rawSkBytes, 32);
    byte[] tradPrivateKeyBytes = Arrays.copyOfRange(rawSkBytes, 32, rawSkBytes.length);

    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            mlDsaPublicKey, SecretBytes.copyFrom(mlDsaSeedBytes, InsecureSecretKeyAccess.get()));
    Ed25519PrivateKey edPrivateKey =
        Ed25519PrivateKey.create(
            edPublicKey, SecretBytes.copyFrom(tradPrivateKeyBytes, InsecureSecretKeyAccess.get()));

    return CompositeMlDsaPrivateKey.builder()
        .setParameters(parameters)
        .setMlDsaPrivateKey(mlDsaPrivateKey)
        .setClassicalPrivateKey(edPrivateKey)
        .setIdRequirement(idRequirement)
        .build();
  }

  private CompositeMlDsaKeyCreator() {}
}
