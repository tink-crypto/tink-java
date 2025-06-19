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
import com.google.crypto.tink.aead.XAesGcmKey;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * This primitive implements XAesGcm.
 *
 * @since 1.0.0
 */
@Immutable
public final class XAesGcm implements Aead {

  private static final int IV_SIZE_IN_BYTES = AesGcmJceUtil.IV_SIZE_IN_BYTES;
  private static final int TAG_SIZE_IN_BYTES = AesGcmJceUtil.TAG_SIZE_IN_BYTES;
  private static final int DERIVED_KEY_SIZE_IN_BYTES = 32;
  private static final int MIN_SALT_SIZE_IN_BYTES = 8;
  private static final int MAX_SALT_SIZE_IN_BYTES = 12;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final int saltSize;

  private final Prf cmac;

  @AccessesPartialKey
  private static Prf createCmac(byte[] key) throws GeneralSecurityException {
    return PrfAesCmac.create(
        AesCmacPrfKey.create(
            AesCmacPrfParameters.create(key.length),
            SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get())));
  }

  private XAesGcm(final byte[] key, Bytes outputPrefix, int saltSize)
      throws GeneralSecurityException {
    this.cmac = createCmac(key);
    this.outputPrefix = outputPrefix.toByteArray();
    this.saltSize = saltSize;
  }

  @AccessesPartialKey
  public static Aead create(XAesGcmKey key) throws GeneralSecurityException {
    if (key.getParameters().getSaltSizeBytes() < MIN_SALT_SIZE_IN_BYTES
        || key.getParameters().getSaltSizeBytes() > MAX_SALT_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid salt size");
    }
    return new XAesGcm(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix(),
        key.getParameters().getSaltSizeBytes());
  }

  private byte[] derivePerMessageKey(byte[] salt) throws GeneralSecurityException {
    byte[] derivationBlock1 = new byte[] {0, 1, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    byte[] derivationBlock2 = new byte[] {0, 2, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (salt.length > MAX_SALT_SIZE_IN_BYTES || salt.length < MIN_SALT_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid salt size");
    }
    System.arraycopy(salt, 0, derivationBlock1, 4, salt.length);
    System.arraycopy(salt, 0, derivationBlock2, 4, salt.length);

    byte[] key = new byte[DERIVED_KEY_SIZE_IN_BYTES];
    System.arraycopy(cmac.compute(derivationBlock1, 16), 0, key, 0, 16);
    System.arraycopy(cmac.compute(derivationBlock2, 16), 0, key, 16, 16);
    return key;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (plaintext == null) {
      throw new NullPointerException("plaintext is null");
    }
    byte[] saltAndIv = Random.randBytes(saltSize + IV_SIZE_IN_BYTES);
    byte[] salt = Arrays.copyOf(saltAndIv, saltSize);
    byte[] iv = Arrays.copyOfRange(saltAndIv, saltSize, saltSize + IV_SIZE_IN_BYTES);

    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(derivePerMessageKey(salt));

    byte[] ciphertext =
        gcm.encrypt(iv, plaintext, outputPrefix.length + saltSize + iv.length, associatedData);

    // add output prefix, salt, iv, and to ciphertext
    System.arraycopy(outputPrefix, 0, ciphertext, 0, outputPrefix.length);
    System.arraycopy(saltAndIv, 0, ciphertext, outputPrefix.length, saltAndIv.length);

    return ciphertext;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext == null) {
      throw new NullPointerException("ciphertext is null");
    }
    if (ciphertext.length < outputPrefix.length + saltSize + IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    int prefixAndSaltSize = outputPrefix.length + saltSize;
    InsecureNonceAesGcmJce gcm =
        new InsecureNonceAesGcmJce(
            derivePerMessageKey(
                Arrays.copyOfRange(ciphertext, outputPrefix.length, prefixAndSaltSize)));
    return gcm.decrypt(
        Arrays.copyOfRange(ciphertext, prefixAndSaltSize, prefixAndSaltSize + IV_SIZE_IN_BYTES),
        ciphertext,
        prefixAndSaltSize + IV_SIZE_IN_BYTES,
        associatedData);
  }
}
