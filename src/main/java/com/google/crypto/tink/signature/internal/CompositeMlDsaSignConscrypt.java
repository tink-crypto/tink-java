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
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.RawKeySpec;
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

  private static final String MLDSA44_ED25519_SHA512_ALGORITHM = "MLDSA44-Ed25519-SHA512";
  private static final int MLDSA44_ED25519_SHA512_SIG_LENGTH = 2420 + 64;

  private static final String MLDSA65_ED25519_SHA512_ALGORITHM = "MLDSA65-Ed25519-SHA512";
  private static final int MLDSA65_ED25519_SHA512_SIG_LENGTH = 3309 + 64;

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

  @AccessesPartialKey
  public static PublicKeySign createWithProvider(
      CompositeMlDsaPrivateKey privateKey, Provider provider) throws GeneralSecurityException {
    Provider nonNullProvider = Objects.requireNonNull(provider);
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      throw new GeneralSecurityException("Composite ML-DSA is not supported in this environment.");
    }
    CompositeMlDsaParameters params = privateKey.getParameters();
    if (params.getClassicalAlgorithm() != ClassicalAlgorithm.ED25519) {
      throw new GeneralSecurityException(
          "Only Ed25519 is supported for composite signatures at this time");
    }

    byte[] mlDsaSeed =
        privateKey.getMlDsaPrivateKey().getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get());
    byte[] ed25519Seed =
        ((Ed25519PrivateKey) privateKey.getClassicalPrivateKey())
            .getPrivateKeyBytes()
            .toByteArray(InsecureSecretKeyAccess.get());

    byte[] rawKeyBytes = new byte[mlDsaSeed.length + ed25519Seed.length];
    System.arraycopy(mlDsaSeed, 0, rawKeyBytes, 0, mlDsaSeed.length);
    System.arraycopy(ed25519Seed, 0, rawKeyBytes, mlDsaSeed.length, ed25519Seed.length);

    String algorithm;
    int signatureLength;
    PrivateKey conscryptPrivateKey;
    if (params.getMlDsaInstance() == MlDsaInstance.ML_DSA_44) {
      algorithm = MLDSA44_ED25519_SHA512_ALGORITHM;
      signatureLength = MLDSA44_ED25519_SHA512_SIG_LENGTH;
      conscryptPrivateKey =
          KeyFactory.getInstance(MLDSA44_ED25519_SHA512_ALGORITHM, nonNullProvider)
              .generatePrivate(new RawKeySpec(rawKeyBytes));
    } else if (params.getMlDsaInstance() == MlDsaInstance.ML_DSA_65) {
      algorithm = MLDSA65_ED25519_SHA512_ALGORITHM;
      signatureLength = MLDSA65_ED25519_SHA512_SIG_LENGTH;
      conscryptPrivateKey =
          KeyFactory.getInstance(MLDSA65_ED25519_SHA512_ALGORITHM, nonNullProvider)
              .generatePrivate(new RawKeySpec(rawKeyBytes));
    } else {
      throw new GeneralSecurityException(
          "Unsupported ML-DSA instance: " + params.getMlDsaInstance());
    }

    // Verify that the public key and the private key match by creating and verifying a dummy
    // signature (this was not verified when the private key was constructed as JCE doesn't
    // provide this functionality).
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
    // We allocate the signature array in advance to avoid copying the ~2-3KB signature array when
    // we don't have to.
    byte[] signature = new byte[outputPrefix.length + signatureLength];
    if (outputPrefix.length > 0) {
      System.arraycopy(outputPrefix, 0, signature, 0, outputPrefix.length);
    }
    signer.sign(signature, outputPrefix.length, signatureLength);
    return signature;
  }
}
