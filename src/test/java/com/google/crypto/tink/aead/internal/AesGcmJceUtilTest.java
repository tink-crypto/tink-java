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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesGcmJceUtilTest {

  @Test
  public void encryptDecrypt_works() throws Exception {
    byte[] keyValue = Random.randBytes(16);
    byte[] plaintext = Random.randBytes(100);

    SecretKey secretKey = AesGcmJceUtil.getSecretKey(keyValue);
    byte[] iv = Random.randBytes(AesGcmJceUtil.IV_SIZE_IN_BYTES);

    Cipher cipher = AesGcmJceUtil.getThreadLocalCipher();

    AlgorithmParameterSpec encParams = AesGcmJceUtil.getParams(iv);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, encParams);
    byte[] ciphertext = cipher.doFinal(plaintext);

    int offset = 7;
    byte[] buf = Bytes.concat(Random.randBytes(offset), iv, Random.randBytes(3));
    AlgorithmParameterSpec decParams =
        AesGcmJceUtil.getParams(buf, offset, AesGcmJceUtil.IV_SIZE_IN_BYTES);
    cipher.init(Cipher.DECRYPT_MODE, secretKey, decParams);
    byte[] decrypted = cipher.doFinal(ciphertext);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void getSecretKey_validatesKeySize() throws Exception {
    assertThat(AesGcmJceUtil.getSecretKey(Random.randBytes(16))).isNotNull();
    assertThat(AesGcmJceUtil.getSecretKey(Random.randBytes(32))).isNotNull();
    assertThrows(
        GeneralSecurityException.class, () -> AesGcmJceUtil.getSecretKey(Random.randBytes(15)));
    assertThrows(
        GeneralSecurityException.class, () -> AesGcmJceUtil.getSecretKey(Random.randBytes(17)));
    assertThrows(
        GeneralSecurityException.class, () -> AesGcmJceUtil.getSecretKey(Random.randBytes(31)));
    assertThrows(
        GeneralSecurityException.class, () -> AesGcmJceUtil.getSecretKey(Random.randBytes(33)));
    assertThrows(
        GeneralSecurityException.class, () -> AesGcmJceUtil.getSecretKey(Random.randBytes(64)));
  }
}
