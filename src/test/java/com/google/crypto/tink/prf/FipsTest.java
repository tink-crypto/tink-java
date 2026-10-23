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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.prf.subtle.AesCmacPrf;
import com.google.crypto.tink.prf.subtle.HkdfPrf;
import com.google.crypto.tink.prf.subtle.HmacPrf;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for the prf package which run under FIPS mode.
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
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void prfConfig2026() throws Exception {
    assertThat(PrfConfig2026.get()).isNotNull();

    HmacPrfParameters hmacParams =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfParameters hkdfParams =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    AesCmacPrfParameters aesCmacParams = AesCmacPrfParameters.create(32);

    KeysetHandle hmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        HmacPrfKey.builder()
                            .setParameters(hmacParams)
                            .setKeyBytes(
                                SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
                            .build())
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle hkdfHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        HkdfPrfKey.builder()
                            .setParameters(hkdfParams)
                            .setKeyBytes(
                                SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
                            .build())
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle aesCmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacPrfKey.create(
                            aesCmacParams,
                            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get())))
                    .withRandomId()
                    .makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(hkdfParams, PrfConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(aesCmacParams, PrfConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> hkdfHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> aesCmacHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class));
    } else {
      assertThat(KeysetHandle.generateNew(hkdfParams, PrfConfig2026.get())).isNotNull();
      assertThat(KeysetHandle.generateNew(aesCmacParams, PrfConfig2026.get())).isNotNull();
      assertThat(hkdfHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class)).isNotNull();
      assertThat(aesCmacHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class)).isNotNull();
    }

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(hmacParams, PrfConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> hmacHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class));
    } else {
      assertThat(KeysetHandle.generateNew(hmacParams, PrfConfig2026.get())).isNotNull();
      assertThat(hmacHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class)).isNotNull();
    }
  }

  @Test
  public void hkdfStreamingPrfConstructor() throws Exception {
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          IllegalStateException.class,
          () -> new HkdfStreamingPrf(HashType.SHA256, new byte[32], new byte[32]));
    } else {
      assertThat(new HkdfStreamingPrf(HashType.SHA256, new byte[32], new byte[32])).isNotNull();
    }
  }

  @Test
  public void hkdfStreamingPrfCreate() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> HkdfStreamingPrf.create(key));
    } else {
      assertThat(HkdfStreamingPrf.create(key)).isNotNull();
    }
  }

  @Test
  public void hkdfPrfCreate() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> HkdfPrf.create(key));
    } else {
      assertThat(HkdfPrf.create(key)).isNotNull();
    }
  }

  @Test
  public void prfAesCmacConstructor() throws Exception {
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> new PrfAesCmac(new byte[32]));
    } else {
      assertThat(new PrfAesCmac(new byte[32])).isNotNull();
    }
  }

  @Test
  public void aesCmacPrfCreate() throws Exception {
    AesCmacPrfKey key =
        AesCmacPrfKey.create(
            AesCmacPrfParameters.create(32),
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()));
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesCmacPrf.create(key));
    } else {
      assertThat(AesCmacPrf.create(key)).isNotNull();
    }
  }

  @Test
  public void prfHmacJceConstructor() throws Exception {
    SecretKeySpec spec = new SecretKeySpec(new byte[32], "HMAC");
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> new PrfHmacJce("HMACSHA256", spec));
    } else {
      assertThat(new PrfHmacJce("HMACSHA256", spec)).isNotNull();
    }
  }

  @Test
  public void hmacPrfCreate() throws Exception {
    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HmacPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> HmacPrf.create(key));
    } else {
      assertThat(HmacPrf.create(key)).isNotNull();
    }
  }
}
