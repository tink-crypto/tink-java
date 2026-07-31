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

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpkeKeyCreator}. */
@RunWith(JUnit4.class)
public final class HpkeKeyCreatorTest {

  @Test
  public void createKey_x25519_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_x25519_raw_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_p256_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 456);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(456);
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_p384_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 789);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(789);
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_p521_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 101112);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(101112);
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_xwing_works() throws Exception {
    Assume.assumeTrue(isXwingHpkeSupported());
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.X_WING)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 131415);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(131415);
    assertThat(key.getPublicKey().getPublicKeyBytes()).isNotNull();
    assertThat(key.getPrivateKeyBytes()).isNotNull();
  }

  @Test
  public void createKey_x25519_calledTwice_createsDifferentKeys() throws Exception {
    int numKeys = 2;
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createKey_p256_calledTwice_createsDifferentKeys() throws Exception {
    int numKeys = 2;
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createKey_xwing_calledTwice_createsDifferentKeys() throws Exception {
    Assume.assumeTrue(isXwingHpkeSupported());
    int numKeys = 2;
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.X_WING)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      HpkePrivateKey key = HpkeKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  // TODO(b/498579995): remove once X-WING HPKE is available in the OSS.
  private static boolean isXwingHpkeSupported() {
    if (!AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      return false;
    }

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
}
