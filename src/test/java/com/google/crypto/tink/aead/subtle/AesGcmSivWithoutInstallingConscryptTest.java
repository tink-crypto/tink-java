// Copyright 2026 Google LLC
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

package com.google.crypto.tink.aead.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class AesGcmSivWithoutInstallingConscryptTest {
  @Test
  public void encryptDecrypt_withoutInstallingConscrypt() throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid());
    Conscrypt.checkAvailability();
    assertNull(Security.getProvider("Conscrypt"));

    byte[] aad = new byte[] {1, 2, 3};
    for (int keySize : new int[] {16, 32}) {
      byte[] key = Random.randBytes(keySize);
      AesGcmSiv gcm = new AesGcmSiv(key);
      byte[] message = Random.randBytes(77);
      byte[] ciphertext = gcm.encrypt(message, aad);
      byte[] decrypted = gcm.decrypt(ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }
}
