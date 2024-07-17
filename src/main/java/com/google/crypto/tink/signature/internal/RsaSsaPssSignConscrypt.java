// Copyright 2024 Google LLC
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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;

/** RSA SSA PSS signing with Conscrypt. */
@Immutable
public final class RsaSsaPssSignConscrypt implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] LEGACY_MESSAGE_SUFFIX = new byte[] {0};

  /** Returns true if Conscrypt is available and supports RSA SSA PSS. */
  public static boolean isSupported() {
    return RsaSsaPssVerifyConscrypt.isSupported();
  }

  @SuppressWarnings("Immutable")
  private final RSAPrivateCrtKey privateKey;

  private final String signatureAlgorithm;

  @SuppressWarnings("Immutable")
  private final PSSParameterSpec parameterSpec;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @AccessesPartialKey
  public static PublicKeySign create(RsaSsaPssPrivateKey key) throws GeneralSecurityException {
    if (!isSupported()) {
      throw new GeneralSecurityException("RSA SSA PSS using Conscrypt is not supported.");
    }
    KeyFactory keyFactory = KeyFactory.getInstance("RSA", RsaSsaPssVerifyConscrypt.CONSCRYPT);
    RsaSsaPssParameters params = key.getParameters();
    RSAPrivateCrtKey privateKey =
        (RSAPrivateCrtKey)
            keyFactory.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    key.getPublicKey().getModulus(),
                    params.getPublicExponent(),
                    key.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    key.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    return new RsaSsaPssSignConscrypt(
        privateKey,
        params.getSigHashType(),
        params.getMgf1HashType(),
        params.getSaltLengthBytes(),
        key.getOutputPrefix().toByteArray(),
        params.getVariant().equals(RsaSsaPssParameters.Variant.LEGACY)
            ? LEGACY_MESSAGE_SUFFIX
            : EMPTY);
  }

  private RsaSsaPssSignConscrypt(
      final RSAPrivateCrtKey privateKey,
      RsaSsaPssParameters.HashType sigHash,
      RsaSsaPssParameters.HashType mgf1Hash,
      int saltLength,
      byte[] outputPrefix,
      byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use RSA PSS in FIPS-mode, as BoringCrypto module is not available.");
    }
    Validators.validateRsaModulusSize(privateKey.getModulus().bitLength());
    Validators.validateRsaPublicExponent(privateKey.getPublicExponent());
    this.privateKey = privateKey;
    this.signatureAlgorithm = RsaSsaPssVerifyConscrypt.getConscryptRsaSsaPssAlgo(sigHash);
    this.parameterSpec =
        RsaSsaPssVerifyConscrypt.getPssParameterSpec(sigHash, mgf1Hash, saltLength);
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    Signature signer =
        Signature.getInstance(signatureAlgorithm, RsaSsaPssVerifyConscrypt.CONSCRYPT);
    signer.initSign(privateKey);
    signer.setParameter(parameterSpec);
    signer.update(data);
    if (messageSuffix.length > 0) {
      signer.update(messageSuffix);
    }
    byte[] signature = signer.sign();
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}
