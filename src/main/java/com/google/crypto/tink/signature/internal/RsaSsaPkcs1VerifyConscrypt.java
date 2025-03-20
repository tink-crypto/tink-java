// Copyright 2018 Google Inc.
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
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.annotation.Nullable;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) using PKCS1-v1_5 encoding) verifying
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1VerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] legacyMessageSuffix = new byte[] {0};

  // TODO(b/182987934) Make the dependance on Conscrypt static.
  @Nullable
  static Provider conscryptProviderOrNull() {
    if (Util.isAndroid() && Util.getAndroidApiLevel() <= 21) {
      // On Android API level 21 or lower, there is a bug in Conscrypt, so we don't
      // want to use that version.
      return null;
    }
    return ConscryptUtil.providerOrNull();
  }

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final String signatureAlgorithm;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @SuppressWarnings("Immutable")
  private final Provider conscrypt;

  public static String toRsaSsaPkcs1Algo(RsaSsaPkcs1Parameters.HashType hashType)
      throws GeneralSecurityException {
    if (hashType == RsaSsaPkcs1Parameters.HashType.SHA256) {
      return "SHA256withRSA";
    }
    if (hashType == RsaSsaPkcs1Parameters.HashType.SHA384) {
      return "SHA384withRSA";
    }
    if (hashType == RsaSsaPkcs1Parameters.HashType.SHA512) {
      return "SHA512withRSA";
    }
    throw new GeneralSecurityException("unknown hash type");
  }

  /**
   * Returns a new instance of PublicKeyVerify for RsaSsaPkcs1 that uses Conscrypt.
   *
   * <p>If Conscrypt is not available, this will throw a GeneralSecurityException.
   *
   * <p>If FIPS mode is enabled but BoringCrypto is not available, this will throw a
   * GeneralSecurityException.
   */
  public static PublicKeyVerify create(RsaSsaPkcs1PublicKey key) throws GeneralSecurityException {
    Provider conscrypt = conscryptProviderOrNull();
    if (conscrypt == null) {
      throw new NoSuchProviderException("RSA-PKCS1.5 using Conscrypt is not supported.");
    }
    return createWithConscryptProvider(key, conscrypt);
  }

  @AccessesPartialKey
  static PublicKeyVerify createWithConscryptProvider(RsaSsaPkcs1PublicKey key, Provider conscrypt)
      throws GeneralSecurityException {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA", conscrypt);
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(key.getModulus(), key.getParameters().getPublicExponent()));

    return new RsaSsaPkcs1VerifyConscrypt(
        publicKey,
        key.getParameters().getHashType(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(RsaSsaPkcs1Parameters.Variant.LEGACY)
            ? legacyMessageSuffix
            : EMPTY,
        conscrypt);
  }

  private RsaSsaPkcs1VerifyConscrypt(
      final RSAPublicKey pubKey,
      RsaSsaPkcs1Parameters.HashType hashType,
      byte[] outputPrefix,
      byte[] messageSuffix,
      Provider conscrypt)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA-PKCS1.5 in FIPS-mode, as BoringCrypto module is not available.");
    }
    Validators.validateRsaModulusSize(pubKey.getModulus().bitLength());
    Validators.validateRsaPublicExponent(pubKey.getPublicExponent());
    this.publicKey = pubKey;
    this.signatureAlgorithm = toRsaSsaPkcs1Algo(hashType);
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
    this.conscrypt = conscrypt;
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    Signature verifier = Signature.getInstance(signatureAlgorithm, conscrypt);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (messageSuffix.length > 0) {
      verifier.update(messageSuffix);
    }
    boolean verified = false;
    try {
      byte[] signatureNoPrefix =
          Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
      verified = verifier.verify(signatureNoPrefix);
    } catch (RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }
}
