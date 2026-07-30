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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaPublicKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.RawKeySpec;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/** Composite ML-DSA verifying with Conscrypt. */
@Immutable
public final class CompositeMlDsaVerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final String MLDSA44_ED25519_SHA512_ALGORITHM = "MLDSA44-Ed25519-SHA512";
  private static final int MLDSA44_ED25519_SHA512_SIG_LENGTH = 2420 + 64;

  private static final String MLDSA65_ED25519_SHA512_ALGORITHM = "MLDSA65-Ed25519-SHA512";
  private static final int MLDSA65_ED25519_SHA512_SIG_LENGTH = 3309 + 64;

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable") // We do not change the public key
  private final PublicKey publicKey;

  private final String algorithm;
  private final int signatureLength;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private CompositeMlDsaVerifyConscrypt(
      byte[] outputPrefix,
      PublicKey publicKey,
      String algorithm,
      int signatureLength,
      Provider provider) {
    this.outputPrefix = outputPrefix;
    this.publicKey = publicKey;
    this.algorithm = algorithm;
    this.signatureLength = signatureLength;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static PublicKeyVerify createWithProvider(
      CompositeMlDsaPublicKey publicKey, Provider provider) throws GeneralSecurityException {
    Provider nonNullProvider = Objects.requireNonNull(provider);
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use Composite ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    CompositeMlDsaParameters params = publicKey.getParameters();
    if (params.getClassicalAlgorithm() != ClassicalAlgorithm.ED25519) {
      throw new GeneralSecurityException(
          "Only Ed25519 is supported for composite signatures at this time");
    }

    byte[] mlDsaBytes = publicKey.getMlDsaPublicKey().getSerializedPublicKey().toByteArray();
    byte[] ed25519Bytes =
        ((Ed25519PublicKey) publicKey.getClassicalPublicKey()).getPublicKeyBytes().toByteArray();

    byte[] rawKeyBytes = new byte[mlDsaBytes.length + ed25519Bytes.length];
    System.arraycopy(mlDsaBytes, 0, rawKeyBytes, 0, mlDsaBytes.length);
    System.arraycopy(ed25519Bytes, 0, rawKeyBytes, mlDsaBytes.length, ed25519Bytes.length);

    String algorithm;
    int signatureLength;
    PublicKey conscryptPublicKey;
    if (params.getMlDsaInstance() == MlDsaInstance.ML_DSA_44) {
      algorithm = MLDSA44_ED25519_SHA512_ALGORITHM;
      signatureLength = MLDSA44_ED25519_SHA512_SIG_LENGTH;
      conscryptPublicKey =
          KeyFactory.getInstance(MLDSA44_ED25519_SHA512_ALGORITHM, nonNullProvider)
              .generatePublic(new RawKeySpec(rawKeyBytes));
    } else if (params.getMlDsaInstance() == MlDsaInstance.ML_DSA_65) {
      algorithm = MLDSA65_ED25519_SHA512_ALGORITHM;
      signatureLength = MLDSA65_ED25519_SHA512_SIG_LENGTH;
      conscryptPublicKey =
          KeyFactory.getInstance(MLDSA65_ED25519_SHA512_ALGORITHM, nonNullProvider)
              .generatePublic(new RawKeySpec(rawKeyBytes));
    } else {
      throw new GeneralSecurityException(
          "Unsupported ML-DSA instance: " + params.getMlDsaInstance());
    }

    return new CompositeMlDsaVerifyConscrypt(
        publicKey.getOutputPrefix().toByteArray(),
        conscryptPublicKey,
        algorithm,
        signatureLength,
        nonNullProvider);
  }

  @AccessesPartialKey
  public static PublicKeyVerify create(CompositeMlDsaPublicKey publicKey)
      throws GeneralSecurityException {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    return createWithProvider(publicKey, provider);
  }

  @Override
  public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    // We cannot check the signature length for ECDSA, but where we can, we do.
    if (signature.length != outputPrefix.length + signatureLength) {
      throw new GeneralSecurityException("Invalid signature length");
    }
    Signature verifier = Signature.getInstance(algorithm, provider);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (!verifier.verify(signature, outputPrefix.length, signatureLength)) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }

  /**
   * Returns true if we're not in FIPS, and Conscrypt is available and supports Composite ML-DSA.
   */
  public static boolean isSupported() {
    if (!FIPS.isCompatible()) {
      return false;
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }

    try {
      KeyFactory unusedKeyFactory44 =
          KeyFactory.getInstance(MLDSA44_ED25519_SHA512_ALGORITHM, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
