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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;

/**
 * ECDSA signing with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaSignJce implements PublicKeySign {

  @SuppressWarnings("Immutable")
  private final PublicKeySign signer;

  public static PublicKeySign create(EcdsaPrivateKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaSignJce.create(key);
  }

  public EcdsaSignJce(final ECPrivateKey privateKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this.signer =
        new com.google.crypto.tink.signature.internal.EcdsaSignJce(privateKey, hash, encoding);
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    return signer.sign(data);
  }
}
