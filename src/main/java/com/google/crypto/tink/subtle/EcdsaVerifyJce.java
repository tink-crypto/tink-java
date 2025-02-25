// Copyright 2017 Google LLC
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

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/**
 * ECDSA verifying with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaVerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final PublicKeyVerify verifier;



  public static PublicKeyVerify create(EcdsaPublicKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaVerifyJce.create(key);
  }

  public EcdsaVerifyJce(final ECPublicKey publicKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this.verifier = new com.google.crypto.tink.signature.internal.EcdsaVerifyJce(publicKey, hash, encoding);
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    verifier.verify(signature, data);
  }
}
