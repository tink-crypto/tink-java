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

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Insecure version of {@link com.google.crypto.tink.subtle.AesGcmJce} that allows the caller to set
 * the IV.
 */
public final class InsecureNonceAesGcmJce {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  // All instances of this class use a 12-byte IV and a 16-byte tag.
  public static final int IV_SIZE_IN_BYTES = AesGcmJceUtil.IV_SIZE_IN_BYTES;
  public static final int TAG_SIZE_IN_BYTES = AesGcmJceUtil.TAG_SIZE_IN_BYTES;

  private final SecretKey keySpec;

  public InsecureNonceAesGcmJce(final byte[] key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    this.keySpec = AesGcmJceUtil.getSecretKey(key);
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  public byte[] encrypt(final byte[] iv, final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (iv.length != IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("iv is wrong size");
    }
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    AlgorithmParameterSpec params = AesGcmJceUtil.getParams(iv);
    Cipher localCipher = AesGcmJceUtil.getThreadLocalCipher();
    localCipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.updateAAD(associatedData);
    }
    return localCipher.doFinal(plaintext);
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  public byte[] decrypt(final byte[] iv, final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (iv.length != IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("iv is wrong size");
    }
    if (ciphertext.length < TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    AlgorithmParameterSpec params = AesGcmJceUtil.getParams(iv);
    Cipher localCipher = AesGcmJceUtil.getThreadLocalCipher();
    localCipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.updateAAD(associatedData);
    }
    return localCipher.doFinal(ciphertext);
  }
}
