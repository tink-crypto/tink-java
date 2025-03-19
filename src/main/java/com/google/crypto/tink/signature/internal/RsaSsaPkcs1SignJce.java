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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) with PKCS1-v1_5 encoding) signing
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1SignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] legacyMessageSuffix = new byte[] {0};
  private static final byte[] testData = new byte[] {1, 2, 3};

  @SuppressWarnings("Immutable")
  private final RSAPrivateCrtKey privateKey;

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final String signatureAlgorithm;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  private static void validateHash(RsaSsaPkcs1Parameters.HashType hash)
      throws GeneralSecurityException {
    if (hash == RsaSsaPkcs1Parameters.HashType.SHA256
        || hash == RsaSsaPkcs1Parameters.HashType.SHA384
        || hash == RsaSsaPkcs1Parameters.HashType.SHA512) {
      return;
    }
    throw new GeneralSecurityException("Unsupported hash: " + hash);
  }

  private RsaSsaPkcs1SignJce(
      final RSAPrivateCrtKey priv, RsaSsaPkcs1Parameters.HashType hash, byte[] outputPrefix, byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA PKCS1.5 in FIPS-mode, as BoringCrypto module is not available.");
    }

    validateHash(hash);
    Validators.validateRsaModulusSize(priv.getModulus().bitLength());
    Validators.validateRsaPublicExponent(priv.getPublicExponent());
    this.privateKey = priv;
    this.signatureAlgorithm = RsaSsaPkcs1VerifyConscrypt.toRsaSsaPkcs1Algo(hash);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    this.publicKey =
        (RSAPublicKey)
            kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  @AccessesPartialKey
  public static PublicKeySign create(RsaSsaPkcs1PrivateKey key) throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPrivateCrtKey privateKey =
        (RSAPrivateCrtKey)
            kf.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    key.getPublicKey().getModulus(),
                    key.getParameters().getPublicExponent(),
                    key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    PublicKeySign signer =
        new RsaSsaPkcs1SignJce(
            privateKey,
            key.getParameters().getHashType(),
            key.getOutputPrefix().toByteArray(),
            key.getParameters().getVariant().equals(RsaSsaPkcs1Parameters.Variant.LEGACY)
                ? legacyMessageSuffix
                : EMPTY);
    PublicKeyVerify verify = RsaSsaPkcs1VerifyJce.create(key.getPublicKey());
    try {
      verify.verify(signer.sign(testData), testData);
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(
          "RsaSsaPkcs1 signing with private key followed by verifying with public key failed."
              + " The key may be corrupted.",
          e);
    }
    return signer;
  }

  private byte[] noPrefixSign(final byte[] data) throws GeneralSecurityException {
    Signature signer = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(data);
    if (messageSuffix.length > 0) {
      signer.update(messageSuffix);
    }
    byte[] signature = signer.sign();
    // Verify the signature to prevent against faulty signature computation.
    Signature verifier = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (messageSuffix.length > 0) {
      verifier.update(messageSuffix);
    }
    if (!verifier.verify(signature)) {
      throw new IllegalStateException("Security bug: RSA signature computation error");
    }
    return signature;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    byte[] signature = noPrefixSign(data);
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}
