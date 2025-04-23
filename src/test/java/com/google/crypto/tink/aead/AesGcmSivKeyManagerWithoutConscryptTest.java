// Copyright 2025 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesGcmSivKeyManagerWithoutConscryptTest {

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void keyCreation_works() throws Exception {
    Parameters validParameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    assertThat(KeysetHandle.generateNew(validParameters).getAt(0).getKey().getParameters())
        .isEqualTo(validParameters);
  }

  @Test
  public void onJavaOrAndroidBefore30_createFails() throws Exception {
    // Run the test on java and android < 30
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel < 30);

    AesGcmSivKey aesGcmSivKey =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmSivKey).withRandomId().makePrimary())
            .build();
    // On Android < 30, the security provider returns an AES GCM cipher instead of an AES GCM SIV
    // cipher.
    // On Java, this algorithm is only supported by Conscrypt, which we didn't install.
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class));
  }
}
