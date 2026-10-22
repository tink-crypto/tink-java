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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.hybrid.internal.EciesKeyCreator;
import com.google.crypto.tink.hybrid.internal.HpkeKeyCreator;
import com.google.crypto.tink.hybrid.internal.XWingHpkeConscryptDecrypt;
import com.google.crypto.tink.hybrid.internal.XWingHpkeConscryptEncrypt;
import com.google.crypto.tink.hybrid.internal.testing.EciesAeadHkdfTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import com.google.crypto.tink.hybrid.subtle.EciesDecrypt;
import com.google.crypto.tink.hybrid.subtle.EciesEncrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeDecrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeEncrypt;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Hybrid encryption which run under FIPS mode.
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

  private static boolean conscryptSupportsXWing() {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance("XWING", provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Test
  public void hybridConfig2026() throws Exception {
    assertThat(HybridConfig2026.get()).isNotNull();

    EciesPrivateKey eciesPrivateKey =
        (EciesPrivateKey) EciesAeadHkdfTestUtil.createTestVector0().getPrivateKey();
    EciesPublicKey eciesPublicKey = eciesPrivateKey.getPublicKey();
    EciesParameters eciesParams = eciesPrivateKey.getParameters();
    KeysetHandle eciesPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(eciesPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle eciesPublicHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(eciesPublicKey).withRandomId().makePrimary())
            .build();

    HpkePrivateKey hpkePrivateKey =
        (HpkePrivateKey) HpkeTestUtil.createTestVector0().getPrivateKey();
    HpkePublicKey hpkePublicKey = hpkePrivateKey.getPublicKey();
    HpkeParameters hpkeParams = hpkePrivateKey.getParameters();
    KeysetHandle hpkePrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hpkePrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle hpkePublicHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hpkePublicKey).withRandomId().makePrimary())
            .build();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(eciesParams, HybridConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(hpkeParams, HybridConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> eciesPrivateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> eciesPublicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> hpkePrivateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> hpkePublicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class));
    } else {
      assertThat(KeysetHandle.generateNew(eciesParams, HybridConfig2026.get())).isNotNull();
      assertThat(KeysetHandle.generateNew(hpkeParams, HybridConfig2026.get())).isNotNull();
      assertThat(eciesPrivateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class))
          .isNotNull();
      assertThat(eciesPublicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class))
          .isNotNull();
      assertThat(hpkePrivateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class))
          .isNotNull();
      assertThat(hpkePublicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class))
          .isNotNull();
    }
  }

  @Test
  public void eciesAeadHkdfHybridEncryptAndDecrypt() throws Exception {
    EciesPrivateKey privateKey =
        (EciesPrivateKey) EciesAeadHkdfTestUtil.createTestVector0().getPrivateKey();
    EciesPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class, () -> EciesAeadHkdfHybridEncrypt.create(publicKey));
      assertThrows(
          GeneralSecurityException.class, () -> EciesAeadHkdfHybridDecrypt.create(privateKey));
    } else {
      assertThat(EciesAeadHkdfHybridEncrypt.create(publicKey)).isNotNull();
      assertThat(EciesAeadHkdfHybridDecrypt.create(privateKey)).isNotNull();
    }
  }

  @Test
  public void eciesEncryptAndDecryptCreate() throws Exception {
    EciesPrivateKey privateKey =
        (EciesPrivateKey) EciesAeadHkdfTestUtil.createTestVector0().getPrivateKey();
    EciesPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> EciesEncrypt.create(publicKey));
      assertThrows(GeneralSecurityException.class, () -> EciesDecrypt.create(privateKey));
    } else {
      assertThat(EciesEncrypt.create(publicKey)).isNotNull();
      assertThat(EciesDecrypt.create(privateKey)).isNotNull();
    }
  }

  @Test
  public void hpkeEncryptAndDecryptCreate() throws Exception {
    HpkePrivateKey privateKey = (HpkePrivateKey) HpkeTestUtil.createTestVector0().getPrivateKey();
    HpkePublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> HpkeEncrypt.create(publicKey));
      assertThrows(GeneralSecurityException.class, () -> HpkeDecrypt.create(privateKey));
      assertThrows(
          GeneralSecurityException.class,
          () -> com.google.crypto.tink.hybrid.internal.HpkeEncrypt.create(publicKey));
      assertThrows(
          GeneralSecurityException.class,
          () -> com.google.crypto.tink.hybrid.internal.HpkeDecrypt.create(privateKey));
    } else {
      assertThat(HpkeEncrypt.create(publicKey)).isNotNull();
      assertThat(HpkeDecrypt.create(privateKey)).isNotNull();
      assertThat(com.google.crypto.tink.hybrid.internal.HpkeEncrypt.create(publicKey)).isNotNull();
      assertThat(com.google.crypto.tink.hybrid.internal.HpkeDecrypt.create(privateKey)).isNotNull();
    }
  }

  @Test
  public void xWingHpkeConscryptEncryptAndDecryptCreate() throws Exception {
    Assume.assumeTrue(conscryptSupportsXWing());
    assertThat(XWingHpkeConscryptEncrypt.isSupported()).isEqualTo(!TinkFips.useOnlyFips());
    HpkePrivateKey privateKey =
        (HpkePrivateKey) HpkeTestUtil.createHpkeTestVectors()[13].getPrivateKey();
    HpkePublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class, () -> XWingHpkeConscryptEncrypt.create(publicKey));
      assertThrows(
          GeneralSecurityException.class, () -> XWingHpkeConscryptDecrypt.create(privateKey));
    } else {
      assertThat(XWingHpkeConscryptEncrypt.create(publicKey)).isNotNull();
      assertThat(XWingHpkeConscryptDecrypt.create(privateKey)).isNotNull();
    }
  }

  @Test
  public void keyCreatorsCreateKey() throws Exception {
    EciesParameters eciesParameters =
        ((EciesPrivateKey) EciesAeadHkdfTestUtil.createTestVector0().getPrivateKey())
            .getParameters();
    HpkeParameters hpkeParameters =
        ((HpkePrivateKey) HpkeTestUtil.createTestVector0().getPrivateKey()).getParameters();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class, () -> EciesKeyCreator.createKey(eciesParameters, null));
      assertThrows(
          GeneralSecurityException.class, () -> HpkeKeyCreator.createKey(hpkeParameters, null));
    } else {
      assertThat(EciesKeyCreator.createKey(eciesParameters, null)).isNotNull();
      assertThat(HpkeKeyCreator.createKey(hpkeParameters, null)).isNotNull();
    }
  }
}
