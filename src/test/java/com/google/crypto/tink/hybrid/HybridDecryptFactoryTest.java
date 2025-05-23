// Copyright 2022 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link HybridDecryptFactory}. */
@RunWith(JUnit4.class)
public class HybridDecryptFactoryTest {
  @BeforeClass
  public static void setUp() throws Exception {
    HybridConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedHybridDecryptFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive()
      throws Exception {
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    HybridEncrypt encrypter =
        publicHandle.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);

    HybridDecrypt factoryDecrypter = HybridDecryptFactory.getPrimitive(privateHandle);
    HybridDecrypt handleDecrypter =
        privateHandle.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThat(factoryDecrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
    assertThat(handleDecrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> factoryDecrypter.decrypt(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class, () -> handleDecrypter.decrypt(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class, () -> factoryDecrypter.decrypt(invalid, contextInfo));
    assertThrows(
        GeneralSecurityException.class, () -> handleDecrypter.decrypt(invalid, contextInfo));
  }
}
