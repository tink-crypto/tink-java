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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.subtle.AesCmacChunkedMac;
import com.google.crypto.tink.mac.subtle.AesCmacMac;
import com.google.crypto.tink.mac.subtle.HmacChunkedMac;
import com.google.crypto.tink.mac.subtle.HmacMac;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Mac which run under FIPS mode.
 *
 * <p>We test this by tagging the test with "fips" which runs it under three build configurations:
 *
 * <ul>
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=False}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *       and {@code BORINGSSL_FIPS=0} in C++.
 * </ul>
 */
@RunWith(JUnit4.class)
public final class FipsTest {

  @BeforeClass
  public static void setUp() {
    if (!TestUtil.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void macConfig2026() throws Exception {
    assertThat(MacConfig2026.get()).isNotNull();

    AesCmacParameters aesCmacParams = PredefinedMacParameters.AES_CMAC_NO_PREFIX;
    HmacParameters hmacParams = PredefinedMacParameters.HMAC_SHA256_128BITTAG_NO_PREFIX;
    KeysetHandle aesCmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacKey.builder()
                            .setParameters(aesCmacParams)
                            .setAesKeyBytes(
                                SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
                            .build())
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle hmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        HmacKey.builder()
                            .setParameters(hmacParams)
                            .setKeyBytes(
                                SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
                            .build())
                    .withRandomId()
                    .makePrimary())
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(aesCmacParams, MacConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> aesCmacHandle.getPrimitive(MacConfig2026.get(), Mac.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> aesCmacHandle.getPrimitive(MacConfig2026.get(), ChunkedMac.class));
    } else {
      assertThat(KeysetHandle.generateNew(aesCmacParams, MacConfig2026.get())).isNotNull();
      assertThat(aesCmacHandle.getPrimitive(MacConfig2026.get(), Mac.class)).isNotNull();
      assertThat(aesCmacHandle.getPrimitive(MacConfig2026.get(), ChunkedMac.class)).isNotNull();
    }

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(hmacParams, MacConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> hmacHandle.getPrimitive(MacConfig2026.get(), Mac.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> hmacHandle.getPrimitive(MacConfig2026.get(), ChunkedMac.class));
    } else {
      assertThat(KeysetHandle.generateNew(hmacParams, MacConfig2026.get())).isNotNull();
      assertThat(hmacHandle.getPrimitive(MacConfig2026.get(), Mac.class)).isNotNull();
      assertThat(hmacHandle.getPrimitive(MacConfig2026.get(), ChunkedMac.class)).isNotNull();
    }
  }

  @Test
  public void aesCmacMacCreate() throws Exception {
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(PredefinedMacParameters.AES_CMAC_NO_PREFIX)
            .setAesKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesCmacMac.create(key));
    } else {
      assertThat(AesCmacMac.create(key)).isNotNull();
    }
  }

  @Test
  public void aesCmacChunkedMacCreate() throws Exception {
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(PredefinedMacParameters.AES_CMAC_NO_PREFIX)
            .setAesKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesCmacChunkedMac.create(key));
    } else {
      assertThat(AesCmacChunkedMac.create(key)).isNotNull();
    }
  }

  @Test
  public void hmacMacCreate() throws Exception {
    HmacKey key =
        HmacKey.builder()
            .setParameters(PredefinedMacParameters.HMAC_SHA256_128BITTAG_NO_PREFIX)
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> HmacMac.create(key));
    } else {
      assertThat(HmacMac.create(key)).isNotNull();
    }
  }

  @Test
  public void hmacChunkedMacCreate() throws Exception {
    HmacKey key =
        HmacKey.builder()
            .setParameters(PredefinedMacParameters.HMAC_SHA256_128BITTAG_NO_PREFIX)
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> HmacChunkedMac.create(key));
    } else {
      assertThat(HmacChunkedMac.create(key)).isNotNull();
    }
  }

  @Test
  public void prfMacCreateAesCmac() throws Exception {
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(PredefinedMacParameters.AES_CMAC_NO_PREFIX)
            .setAesKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> PrfMac.create(key));
    } else {
      assertThat(PrfMac.create(key)).isNotNull();
    }
  }

  @Test
  public void prfMacCreateHmac() throws Exception {
    HmacKey key =
        HmacKey.builder()
            .setParameters(PredefinedMacParameters.HMAC_SHA256_128BITTAG_NO_PREFIX)
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> PrfMac.create(key));
    } else {
      assertThat(PrfMac.create(key)).isNotNull();
    }
  }
}
