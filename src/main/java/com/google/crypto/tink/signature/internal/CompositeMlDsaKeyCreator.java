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
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.SignaturePrivateKey;
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
  @SuppressWarnings("InsecureCryptoUsage") // We do not use ECB
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
    if (parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P256)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P384)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P521)) {
      throw new GeneralSecurityException(
          "ECDSA is not supported for composite signatures at this time");
    }

    String algorithmName = CompositeMlDsaUtil.getAlgorithmName(parameters);
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmName, provider);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, provider);

    int mlDsaPublicKeySize = CompositeMlDsaUtil.getMlDsaPublicKeySize(parameters);

    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    RawKeySpec pubKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RawKeySpec.class);
    byte[] rawPkBytes = pubKeySpec.getEncoded();
    RawKeySpec privKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RawKeySpec.class);
    byte[] rawSkBytes = privKeySpec.getEncoded();

    byte[] mlDsaPubBytes = Arrays.copyOf(rawPkBytes, mlDsaPublicKeySize);
    byte[] mlDsaSeedBytes = Arrays.copyOf(rawSkBytes, 32);
    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(
                    // Maps CompositeMlDsaParameters to corresponding MlDsaParameters instance.
                    CompositeMlDsaUtil.getMlDsaParametersMlDsaInstance(parameters),
                    MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(Bytes.copyFrom(mlDsaPubBytes))
            .build();
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            mlDsaPublicKey, SecretBytes.copyFrom(mlDsaSeedBytes, InsecureSecretKeyAccess.get()));

    byte[] classicalPubBytes = Arrays.copyOfRange(rawPkBytes, mlDsaPublicKeySize, rawPkBytes.length);
    byte[] classicalPrivateKeyBytes = Arrays.copyOfRange(rawSkBytes, 32, rawSkBytes.length);
    SignaturePrivateKey classicalPrivateKey;
    if (parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.ED25519)) {
      Ed25519PublicKey edPublicKey =
          Ed25519PublicKey.create(
              Ed25519Parameters.Variant.NO_PREFIX, Bytes.copyFrom(classicalPubBytes), null);
      classicalPrivateKey =
          Ed25519PrivateKey.create(
              edPublicKey,
              SecretBytes.copyFrom(classicalPrivateKeyBytes, InsecureSecretKeyAccess.get()));
    } else if (parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PSS)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PSS)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PSS)) {
      classicalPrivateKey =
          CompositeMlDsaUtil.pkcs1RsaKeyToRsaSsaPssPrivateKey(classicalPrivateKeyBytes, parameters);
    } else if (parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PKCS1)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PKCS1)
        || parameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      classicalPrivateKey =
          CompositeMlDsaUtil.pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(classicalPrivateKeyBytes, parameters);
    } else {
      throw new GeneralSecurityException(
          "Unsupported classical algorithm for composite signatures: "
              + parameters.getClassicalAlgorithm());
    }

    return CompositeMlDsaPrivateKey.builder()
        .setParameters(parameters)
        .setMlDsaPrivateKey(mlDsaPrivateKey)
        .setClassicalPrivateKey(classicalPrivateKey)
        .setIdRequirement(idRequirement)
        .build();
  }

  private CompositeMlDsaKeyCreator() {}
}
