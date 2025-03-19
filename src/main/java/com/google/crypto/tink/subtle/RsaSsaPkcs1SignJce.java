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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) with PKCS1-v1_5 encoding) signing
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1SignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final PublicKeySign signer;

  public static PublicKeySign create(RsaSsaPkcs1PrivateKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.RsaSsaPkcs1SignJce.create(key);
  }

  private static RsaSsaPkcs1Parameters.HashType convertHashType(HashType hash) throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return RsaSsaPkcs1Parameters.HashType.SHA256;
      case SHA384:
        return RsaSsaPkcs1Parameters.HashType.SHA384;
      case SHA512:
        return RsaSsaPkcs1Parameters.HashType.SHA512;
      default:
        break;
    }
    throw new GeneralSecurityException("Unsupported hash: " + hash.name());
  }

  @AccessesPartialKey
  private static PublicKeySign getSigner(RSAPrivateCrtKey privateKey, HashType hash)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(privateKey.getModulus().bitLength())
            .setPublicExponent(privateKey.getPublicExponent())
            .setHashType(convertHashType(hash))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(parameters)
            .setModulus(privateKey.getModulus())
            .build();
    RsaSsaPkcs1PrivateKey key =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrimes(
                SecretBigInteger.fromBigInteger(privateKey.getPrimeP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(privateKey.getPrimeQ(), InsecureSecretKeyAccess.get()))
            .setPrivateExponent(SecretBigInteger.fromBigInteger(privateKey.getPrivateExponent(), InsecureSecretKeyAccess.get()))
            .setPrimeExponents(
                SecretBigInteger.fromBigInteger(privateKey.getPrimeExponentP(), InsecureSecretKeyAccess.get()),
                SecretBigInteger.fromBigInteger(privateKey.getPrimeExponentQ(), InsecureSecretKeyAccess.get()))
            .setCrtCoefficient(
                SecretBigInteger.fromBigInteger(privateKey.getCrtCoefficient(), InsecureSecretKeyAccess.get()))
            .build();
    return com.google.crypto.tink.signature.internal.RsaSsaPkcs1SignJce.create(key);
  }

  public RsaSsaPkcs1SignJce(final RSAPrivateCrtKey privateKey, HashType hash)
      throws GeneralSecurityException {
    this.signer = getSigner(privateKey, hash);
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    return signer.sign(data);
  }
}
