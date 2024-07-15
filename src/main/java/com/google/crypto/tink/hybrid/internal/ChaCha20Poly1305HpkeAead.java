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

import com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Poly1305;
import com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Poly1305Jce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

/** ChaCha20-Poly1305 HPKE AEAD variant. */
@Immutable
final class ChaCha20Poly1305HpkeAead implements HpkeAead {
  @Override
  public byte[] seal(
      byte[] key, byte[] nonce, byte[] plaintext, int ciphertextOffset, byte[] associatedData)
      throws GeneralSecurityException {
    if (key.length != getKeyLength()) {
      throw new InvalidAlgorithmParameterException("Unexpected key length: " + getKeyLength());
    }
    if (InsecureNonceChaCha20Poly1305Jce.isSupported()) {
      InsecureNonceChaCha20Poly1305Jce aead = InsecureNonceChaCha20Poly1305Jce.create(key);
      return aead.encrypt(nonce, plaintext, ciphertextOffset, associatedData);
    }
    InsecureNonceChaCha20Poly1305 aead = new InsecureNonceChaCha20Poly1305(key);
    byte[] aeadCiphertext = aead.encrypt(nonce, plaintext, associatedData);
    if (aeadCiphertext.length > Integer.MAX_VALUE - ciphertextOffset) {
      throw new InvalidAlgorithmParameterException("Plaintext too long");
    }
    byte[] ciphertext = new byte[ciphertextOffset + aeadCiphertext.length];
    System.arraycopy(
        /* src= */ aeadCiphertext,
        /* srcPos= */ 0,
        /* dest= */ ciphertext,
        /* destPos= */ ciphertextOffset,
        /* length= */ aeadCiphertext.length);
    return ciphertext;
  }

  @Override
  public byte[] open(
      byte[] key, byte[] nonce, byte[] ciphertext, int ciphertextOffset, byte[] associatedData)
      throws GeneralSecurityException {
    if (key.length != getKeyLength()) {
      throw new InvalidAlgorithmParameterException("Unexpected key length: " + getKeyLength());
    }
    if (InsecureNonceChaCha20Poly1305Jce.isSupported()) {
      InsecureNonceChaCha20Poly1305Jce aead = InsecureNonceChaCha20Poly1305Jce.create(key);
      return aead.decrypt(nonce, ciphertext, ciphertextOffset, associatedData);
    }
    byte[] aeadCiphertext = Arrays.copyOfRange(ciphertext, ciphertextOffset, ciphertext.length);
    InsecureNonceChaCha20Poly1305 aead = new InsecureNonceChaCha20Poly1305(key);
    return aead.decrypt(nonce, aeadCiphertext, associatedData);
  }

  @Override
  public byte[] getAeadId() {
    return HpkeUtil.CHACHA20_POLY1305_AEAD_ID;
  }

  @Override
  public int getKeyLength() {
    // 256-bit key length: https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.
    return 32;
  }

  @Override
  public int getNonceLength() {
    // 96-bit nonce length: https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.
    return 12;
  }
}
