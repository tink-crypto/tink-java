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
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1PureJava;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1VerifyConscrypt;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) using PKCS1-v1_5 encoding) verifying
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1VerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final PublicKeyVerify verify;

  @AccessesPartialKey
  public static PublicKeyVerify create(RsaSsaPkcs1PublicKey key) throws GeneralSecurityException {
    try {
      return RsaSsaPkcs1VerifyConscrypt.create(key);
    } catch (NoSuchProviderException e) {
      // Ignore, and fall back to the Java implementation.
    }
    return RsaSsaPkcs1PureJava.create(key);
  }

  private static RsaSsaPkcs1Parameters.HashType getHashType(HashType hash)
      throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return RsaSsaPkcs1Parameters.HashType.SHA256;
      case SHA384:
        return RsaSsaPkcs1Parameters.HashType.SHA384;
      case SHA512:
        return RsaSsaPkcs1Parameters.HashType.SHA512;
      default:
        throw new GeneralSecurityException("Unsupported hash: " + hash);
    }
  }

  @AccessesPartialKey
  private RsaSsaPkcs1PublicKey convertKey(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(pubKey.getModulus().bitLength())
            .setPublicExponent(pubKey.getPublicExponent())
            .setHashType(getHashType(hash))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(parameters)
        .setModulus(pubKey.getModulus())
        .build();
  }

  // Consider using RsaSsaPkcs1VerifyJce.create instead.
  public RsaSsaPkcs1VerifyJce(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {

    this.verify = create(convertKey(pubKey, hash));
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    verify.verify(signature, data);
  }
}
