// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Hybrid Public Key Encryption (HPKE) encryption.
 *
 * <p>HPKE RFC: https://www.rfc-editor.org/rfc/rfc9180.html
 */
@Immutable
public final class HpkeEncrypt implements HybridEncrypt {
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  @SuppressWarnings("Immutable") // We copy this on creation and never output it.
  private final byte[] recipientPublicKey;

  private final HpkeKem kem;
  private final HpkeKdf kdf;
  private final HpkeAead aead;

  @SuppressWarnings("Immutable") // We copy this on creation and never output it.
  private final byte[] outputPrefix;

  private HpkeEncrypt(
      Bytes recipientPublicKey, HpkeKem kem, HpkeKdf kdf, HpkeAead aead, Bytes outputPrefix) {
    this.recipientPublicKey = recipientPublicKey.toByteArray();
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.outputPrefix = outputPrefix.toByteArray();
  }

  @AccessesPartialKey
  public static HybridEncrypt create(HpkePublicKey key) throws GeneralSecurityException {
    HpkeParameters parameters = key.getParameters();
    return new HpkeEncrypt(
        key.getPublicKeyBytes(),
        HpkePrimitiveFactory.createKem(parameters.getKemId()),
        HpkePrimitiveFactory.createKdf(parameters.getKdfId()),
        HpkePrimitiveFactory.createAead(parameters.getAeadId()),
        key.getOutputPrefix());
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] info = contextInfo;
    if (info == null) {
      info = new byte[0];
    }
    HpkeContext context = HpkeContext.createSenderContext(recipientPublicKey, kem, kdf, aead, info);
    byte[] encapsulatedKey = context.getEncapsulatedKey();
    int ciphertextOffset = outputPrefix.length + encapsulatedKey.length;
    byte[] ciphertextWithPrefix = context.seal(plaintext, ciphertextOffset, EMPTY_ASSOCIATED_DATA);
    // In ciphertextWithPrefix, the ciphertext starts at ciphertextOffset.
    // Copy the outputPrefix and encapsulatedKey to the beginning of ciphertextWithPrefix.
    System.arraycopy(
        /* src= */ outputPrefix,
        /* srcPos= */ 0,
        /* dest= */ ciphertextWithPrefix,
        /* destPos= */ 0,
        /* length= */ outputPrefix.length);
    System.arraycopy(
        /* src= */ encapsulatedKey,
        /* srcPos= */ 0,
        /* dest= */ ciphertextWithPrefix,
        /* destPos= */ outputPrefix.length,
        /* length= */ encapsulatedKey.length);
    return ciphertextWithPrefix;
  }
}
