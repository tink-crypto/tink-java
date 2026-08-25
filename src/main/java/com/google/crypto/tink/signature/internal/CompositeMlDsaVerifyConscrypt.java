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
import com.google.crypto.tink.internal.Asn1Util;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaPublicKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.util.Objects;

/** Composite ML-DSA verifying with Conscrypt. */
@Immutable
public final class CompositeMlDsaVerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final String MLDSA44_ED25519_SHA512_ALGORITHM = "MLDSA44-Ed25519-SHA512";

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

  @SuppressWarnings("InsecureCryptoUsage") // We do not use ECB
  @AccessesPartialKey
  public static PublicKeyVerify createWithProvider(
      CompositeMlDsaPublicKey publicKey, Provider provider) throws GeneralSecurityException {
    Provider nonNullProvider = Objects.requireNonNull(provider);
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use Composite ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    CompositeMlDsaParameters params = publicKey.getParameters();
    if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P256)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P384)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ECDSA_P521)) {
      throw new GeneralSecurityException(
          "ECDSA is not supported for composite signatures at this time");
    }

    byte[] mlDsaBytes = publicKey.getMlDsaPublicKey().getSerializedPublicKey().toByteArray();
    byte[] classicalPublicKeyBytes;
    if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.ED25519)) {
      classicalPublicKeyBytes =
          ((Ed25519PublicKey) publicKey.getClassicalPublicKey()).getPublicKeyBytes().toByteArray();
    } else if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PSS)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PSS)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PSS)) {
      classicalPublicKeyBytes =
          Asn1Util.rsaSsaPssPublicKeyToPkcs1Bytes(
              (RsaSsaPssPublicKey) publicKey.getClassicalPublicKey());
    } else if (params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PKCS1)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PKCS1)
        || params.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      classicalPublicKeyBytes =
          Asn1Util.rsaSsaPkcs1PublicKeyToPkcs1Bytes(
              (RsaSsaPkcs1PublicKey) publicKey.getClassicalPublicKey());
    } else {
      throw new GeneralSecurityException(
          "Unsupported classical algorithm: " + params.getClassicalAlgorithm());
    }

    byte[] rawKeyBytes = new byte[mlDsaBytes.length + classicalPublicKeyBytes.length];
    System.arraycopy(mlDsaBytes, 0, rawKeyBytes, 0, mlDsaBytes.length);
    System.arraycopy(
        classicalPublicKeyBytes, 0, rawKeyBytes, mlDsaBytes.length, classicalPublicKeyBytes.length);

    String algorithm = CompositeMlDsaUtil.getAlgorithmName(params);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm, nonNullProvider);
    PublicKey conscryptPublicKey = keyFactory.generatePublic(new RawKeySpec(rawKeyBytes));
    int signatureLength = CompositeMlDsaUtil.getSignatureLength(params);

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

  @SuppressWarnings("InsecureCryptoUsage") // We do not use ECB
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

  /** Representation of the raw keys for interoperability with Conscrypt. */
  public static final class RawKeySpec extends EncodedKeySpec {
    public RawKeySpec(byte[] encoded) {
      super(encoded);
    }

    @Override
    public String getFormat() {
      return "raw";
    }
  }
}
