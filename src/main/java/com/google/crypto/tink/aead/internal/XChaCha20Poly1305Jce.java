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

package com.google.crypto.tink.aead.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Random;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20Poly1305Jce implements an AEAD for ChaCha20Poly1305, as described in <a
 * href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439, section 2.8</a>.
 *
 * <p>It uses the JCE, and requires that algorithm "ChaCha20-Poly1305" is present.
 */
@Immutable
public final class XChaCha20Poly1305Jce implements Aead {

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final int NONCE_SIZE_IN_BYTES = 24;
  private static final int TAG_SIZE_IN_BYTES = 16;
  private static final int KEY_SIZE_IN_BYTES = 32;

  private static final String KEY_NAME = "ChaCha20";

  @SuppressWarnings("Immutable")
  private final byte[] key;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final Provider provider;

  private XChaCha20Poly1305Jce(final byte[] key, final byte[] outputPrefix, Provider provider)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use ChaCha20Poly1305 in FIPS-mode.");
    }
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("The key length in bytes must be 32.");
    }
    this.key = key;
    this.outputPrefix = outputPrefix;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static Aead create(XChaCha20Poly1305Key key) throws GeneralSecurityException {
    // create a cipher instance to test that they are valid, and to get the provider.
    Cipher cipher = ChaCha20Poly1305Jce.getValidCipherInstance();
    return new XChaCha20Poly1305Jce(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix().toByteArray(),
        cipher.getProvider());
  }

  public static boolean isSupported() {
    return ChaCha20Poly1305Jce.isSupported();
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (plaintext == null) {
      throw new NullPointerException("plaintext is null");
    }
    byte[] nonce = Random.randBytes(NONCE_SIZE_IN_BYTES);
    byte[] subkey = ChaCha20Util.hChaCha20(key, nonce);
    SecretKeySpec keySpec = new SecretKeySpec(subkey, KEY_NAME);
    AlgorithmParameterSpec params = new IvParameterSpec(getChaCha20Nonce(nonce));
    Cipher cipher = ChaCha20Poly1305Jce.getCipherInstance(provider);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int outputSize = cipher.getOutputSize(plaintext.length);
    if (outputSize > Integer.MAX_VALUE - outputPrefix.length - NONCE_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    int len = outputPrefix.length + NONCE_SIZE_IN_BYTES + outputSize;
    byte[] output = Arrays.copyOf(outputPrefix, len);
    System.arraycopy(
        /* src= */ nonce,
        /* srcPos= */ 0,
        /* dest= */ output,
        /* destPos= */ outputPrefix.length,
        /* length= */ NONCE_SIZE_IN_BYTES);
    int written =
        cipher.doFinal(
            plaintext, 0, plaintext.length, output, outputPrefix.length + NONCE_SIZE_IN_BYTES);
    if (written != outputSize) {
      throw new GeneralSecurityException("not enough data written");
    }
    return output;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext == null) {
      throw new NullPointerException("ciphertext is null");
    }
    if (ciphertext.length < outputPrefix.length + NONCE_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    byte[] nonce = new byte[NONCE_SIZE_IN_BYTES];
    System.arraycopy(
        /* src= */ ciphertext,
        /* srcPos= */ outputPrefix.length,
        /* dest= */ nonce,
        /* destPos= */ 0,
        /* length= */ NONCE_SIZE_IN_BYTES);
    byte[] subkey = ChaCha20Util.hChaCha20(key, nonce);
    SecretKeySpec keySpec = new SecretKeySpec(subkey, KEY_NAME);
    AlgorithmParameterSpec params = new IvParameterSpec(getChaCha20Nonce(nonce));
    Cipher cipher = ChaCha20Poly1305Jce.getCipherInstance(provider);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int offset = outputPrefix.length + NONCE_SIZE_IN_BYTES;
    int len = ciphertext.length - outputPrefix.length - NONCE_SIZE_IN_BYTES;
    return cipher.doFinal(ciphertext, offset, len);
  }

  // Returns the last 8 bytes of a 24 bytes nonce, prefixed by 4 null bytes.
  // See https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-01#section-2.3
  static byte[] getChaCha20Nonce(byte[] nonce) {
    byte[] chacha20Nonce = new byte[12];
    System.arraycopy(
        /* src= */ nonce,
        /* srcPos= */ 16,
        /* dest= */ chacha20Nonce,
        /* destPos= */ 4,
        /* length= */ 8);
    return chacha20Nonce;
  }
}
