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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.Asn1Util;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.CompositeMlDsaVerifyConscrypt.RawKeySpec;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;

/** Composite ML-DSA signing with Conscrypt. */
@Immutable
public final class CompositeMlDsaSignConscrypt implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final String TEST_WORKLOAD = "test workload";

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable") // We do not change the private key
  private final PrivateKey privateKey;

  private final String algorithm;
  private final int signatureLength;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private CompositeMlDsaSignConscrypt(
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider) {
    this.outputPrefix = outputPrefix;
    this.privateKey = privateKey;
    this.algorithm = algorithm;
    this.signatureLength = signatureLength;
    this.provider = provider;
  }

  @SuppressWarnings("InsecureCryptoUsage") // We do not use ECB
  @AccessesPartialKey
  public static PublicKeySign createWithProvider(
      CompositeMlDsaPrivateKey privateKey, Provider provider) throws GeneralSecurityException {
    Provider nonNullProvider = Objects.requireNonNull(provider);
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      throw new GeneralSecurityException("Composite ML-DSA is not supported in this environment.");
    }
    CompositeMlDsaParameters params = privateKey.getParameters();
    if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P256)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P384)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P521)) {
      throw new GeneralSecurityException(
          "ECDSA is not supported for composite signatures at this time");
    }

    byte[] mlDsaSeed =
        privateKey.getMlDsaPrivateKey().getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get());
    byte[] classicalPrivateKeyBytes;
    if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ED25519)) {
      classicalPrivateKeyBytes =
          ((Ed25519PrivateKey) privateKey.getClassicalPrivateKey())
              .getPrivateKeyBytes()
              .toByteArray(InsecureSecretKeyAccess.get());
    } else if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PSS)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PSS)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PSS)) {
      classicalPrivateKeyBytes =
          Asn1Util.rsaSsaPssPrivateKeyToPkcs1Bytes(
              (RsaSsaPssPrivateKey) privateKey.getClassicalPrivateKey());
    } else if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PKCS1)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PKCS1)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      classicalPrivateKeyBytes =
          Asn1Util.rsaSsaPkcs1PrivateKeyToPkcs1Bytes(
              (RsaSsaPkcs1PrivateKey) privateKey.getClassicalPrivateKey());
    } else {
      throw new GeneralSecurityException(
          "Unsupported classical algorithm: " + params.getClassicalAlgorithm());
    }

    byte[] rawKeyBytes = new byte[mlDsaSeed.length + classicalPrivateKeyBytes.length];
    System.arraycopy(mlDsaSeed, 0, rawKeyBytes, 0, mlDsaSeed.length);
    System.arraycopy(
        classicalPrivateKeyBytes,
        0,
        rawKeyBytes,
        mlDsaSeed.length,
        classicalPrivateKeyBytes.length);

    String algorithm = CompositeMlDsaUtil.getAlgorithmName(params);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm, nonNullProvider);
    PrivateKey conscryptPrivateKey = keyFactory.generatePrivate(new RawKeySpec(rawKeyBytes));
    int signatureLength = CompositeMlDsaUtil.getSignatureLength(params);

    byte[] testSignature =
        signInternal(
            TEST_WORKLOAD.getBytes(UTF_8),
            privateKey.getOutputPrefix().toByteArray(),
            conscryptPrivateKey,
            algorithm,
            signatureLength,
            nonNullProvider);
    PublicKeyVerify verifier =
        CompositeMlDsaVerifyConscrypt.createWithProvider(
            privateKey.getPublicKey(), nonNullProvider);
    verifier.verify(testSignature, TEST_WORKLOAD.getBytes(UTF_8));

    return new CompositeMlDsaSignConscrypt(
        privateKey.getOutputPrefix().toByteArray(),
        conscryptPrivateKey,
        algorithm,
        signatureLength,
        nonNullProvider);
  }

  @AccessesPartialKey
  public static PublicKeySign create(CompositeMlDsaPrivateKey privateKey)
      throws GeneralSecurityException {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    return createWithProvider(privateKey, provider);
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    return signInternal(data, outputPrefix, privateKey, algorithm, signatureLength, provider);
  }

  @SuppressWarnings("InsecureCryptoUsage") // We do not use ECB
  private static byte[] signInternal(
      byte[] data,
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider)
      throws GeneralSecurityException {
    Signature signer = Signature.getInstance(algorithm, provider);
    signer.initSign(privateKey);
    signer.update(data);
    byte[] signature = new byte[outputPrefix.length + signatureLength];
    if (outputPrefix.length > 0) {
      System.arraycopy(outputPrefix, 0, signature, 0, outputPrefix.length);
    }
    signer.sign(signature, outputPrefix.length, signatureLength);
    return signature;
  }
}
