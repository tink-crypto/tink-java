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

package com.google.crypto.tink.aead;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.LegacyKeysetSerialization;
import java.io.ByteArrayOutputStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class XAesGcmKeyManagerTest {

  @BeforeClass
  public static void setUp() throws Exception {
    XAesGcmKeyManager.register(/* newKeyAllowed= */ true);
  }

  @Test
  public void xAesGcmKeyTypeIsRegistered() throws Exception {
    assertNotNull(
        KeysetHandle.generateNew(PredefinedAeadParameters.X_AES_GCM_8_BYTE_SALT_NO_PREFIX));
  }

  @Test
  public void xAesGcmKeyCreator_generatesNewKey() throws Exception {
    XAesGcmKey key1 =
        (XAesGcmKey)
            KeysetHandle.generateNew(PredefinedAeadParameters.X_AES_GCM_8_BYTE_SALT_NO_PREFIX)
                .getPrimary()
                .getKey();
    XAesGcmKey key2 =
        (XAesGcmKey)
            KeysetHandle.generateNew(PredefinedAeadParameters.X_AES_GCM_8_BYTE_SALT_NO_PREFIX)
                .getPrimary()
                .getKey();

    assertNotEquals(key1, key2);
  }

  @Test
  public void xAesGcmKeyNamesTemplates_areRegistered() throws Exception {
    assertNotNull(
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("X_AES_GCM_8_BYTE_SALT_NO_PREFIX")
                    .withRandomId()
                    .makePrimary())
            .build());
  }

  @Test
  public void xAesGcmKeySerialization_isRegistered() throws Exception {
    KeysetHandle handle =
        KeysetHandle.generateNew(PredefinedAeadParameters.X_AES_GCM_8_BYTE_SALT_NO_PREFIX);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter keysetWriter = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeKeyset(handle, keysetWriter, InsecureSecretKeyAccess.get());
  }
}
