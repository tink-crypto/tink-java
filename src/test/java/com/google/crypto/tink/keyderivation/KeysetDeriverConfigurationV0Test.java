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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.keyderivation.internal.PrfBasedKeyDerivationKeyProtoSerialization;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.internal.HkdfPrfProtoSerialization;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@SuppressWarnings("RestrictedApi")
public class KeysetDeriverConfigurationV0Test {

  @BeforeClass
  public static void setUp() throws Exception {
    HkdfPrfProtoSerialization.register();
    PrfBasedKeyDerivationKeyProtoSerialization.register();
    AesGcmKeyManager.register(true);
  }

  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, KeysetDeriverConfigurationV0::get);
  }

  @Test
  public void config_containsPrfBasedKeyDerivation() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    // Value from PrfBasedKeyDerivationKeyTest.java
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfKey.getParameters())
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();
    PrfBasedKeyDerivationKey key = PrfBasedKeyDerivationKey.create(parameters, prfKey, null);
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();

    assertThat(handle.getPrimitive(KeysetDeriverConfigurationV0.get(), KeysetDeriver.class))
        .isNotNull();
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class));
  }

  @Test
  public void config_handlesLegacyKey() throws Exception {
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    PrfBasedKeyDerivationKey key =
        PrfBasedKeyDerivationKey.create(
            PrfBasedKeyDerivationParameters.builder()
                .setPrfParameters(prfKey.getParameters())
                .setDerivedKeyParameters(
                    AesGcmParameters.builder()
                        .setKeySizeBytes(16)
                        .setIvSizeBytes(12)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build(),
            prfKey,
            null);
    ProtoKeySerialization serialization =
        MutableSerializationRegistry.globalInstance()
            .serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    LegacyProtoKey legacyKey = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(legacyKey).withFixedId(123).makePrimary())
            .build();

    assertThat(handle.getPrimitive(KeysetDeriverConfigurationV0.get(), KeysetDeriver.class))
        .isNotNull();
  }
}
