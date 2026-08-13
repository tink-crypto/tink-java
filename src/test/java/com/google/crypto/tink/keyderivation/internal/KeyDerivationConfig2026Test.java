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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.keyderivation.internal.test.PrfBasedKeyDeriverTestVectors;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyDerivationConfig2026}. */
@RunWith(JUnit4.class)
public class KeyDerivationConfig2026Test {

  @BeforeClass
  public static void setUp() throws Exception {
    AesGcmKeyManager.register(true);
  }

  private static PrfBasedKeyDerivationKey createTestKey() throws GeneralSecurityException {
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
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .build();
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfKey.getParameters())
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();
    return PrfBasedKeyDerivationKey.create(parameters, prfKey, null);
  }

  @Test
  public void get_isNotNull() throws Exception {
    assertThat(KeyDerivationConfig2026.get()).isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    PrfBasedKeyDerivationKey key = createTestKey();
    KeysetHandle handle =
        KeysetHandle.generateNew(key.getParameters(), KeyDerivationConfig2026.get());

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Test
  public void serializeAndParseKey_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    PrfBasedKeyDerivationKey key = createTestKey();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            handle, InsecureSecretKeyAccess.get(), KeyDerivationConfig2026.get());
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeyset, InsecureSecretKeyAccess.get(), KeyDerivationConfig2026.get());

    assertThat(parsedHandle.size()).isEqualTo(1);
    assertThat(parsedHandle.getAt(0).getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Test
  public void serializeAndParseParameters_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    PrfBasedKeyDerivationKey key = createTestKey();
    Parameters parameters = key.getParameters();
    byte[] serialized =
        TinkProtoParametersFormat.serialize(parameters, KeyDerivationConfig2026.get());
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, KeyDerivationConfig2026.get());

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void createPrimitive_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    PrfBasedKeyDerivationKey key = createTestKey();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();

    KeysetDeriver deriver = handle.getPrimitive(KeyDerivationConfig2026.get(), KeysetDeriver.class);
    assertThat(deriver).isNotNull();

    KeysetHandle derivedKeyset = deriver.deriveKeyset(new byte[] {1, 2, 3});
    assertThat(derivedKeyset.size()).isEqualTo(1);
  }

  @Test
  public void testVectors_deriveKeyset_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    for (PrfBasedKeyDeriverTestVectors.TestVector t :
        PrfBasedKeyDeriverTestVectors.createTestVectors()) {
      PrfBasedKeyDerivationParameters derivationParameters =
          PrfBasedKeyDerivationParameters.builder()
              .setPrfParameters(t.prfKey.getParameters())
              .setDerivedKeyParameters(t.derivedKeyParameters)
              .build();
      Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
      PrfBasedKeyDerivationKey key =
          PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);

      KeysetHandle handle =
          KeysetHandle.newBuilder()
              .addEntry(
                  KeysetHandle.importKey(key)
                      .withFixedId(idRequirement == null ? 789789 : idRequirement)
                      .makePrimary())
              .build();

      KeysetDeriver deriver =
          handle.getPrimitive(KeyDerivationConfig2026.get(), KeysetDeriver.class);
      KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode(t.inputHex));

      assertThat(derivedKeyset.size()).isEqualTo(1);
      assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(t.derivedKeyParameters);
      assertThat(derivedKeyset.getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(idRequirement);
      assertThat(derivedKeyset.getAt(0).getKey().equalsKey(t.expectedKey)).isTrue();
    }
  }

  @Test
  public void testVector_aesGcmSiv_deriveKeyset_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    PrfBasedKeyDeriverTestVectors.TestVector t =
        PrfBasedKeyDeriverTestVectors.createAesGcmSivTestVector();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(t.prfKey.getParameters())
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .build();
    Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey key =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key)
                    .withFixedId(idRequirement == null ? 789789 : idRequirement)
                    .makePrimary())
            .build();

    KeysetDeriver deriver = handle.getPrimitive(KeyDerivationConfig2026.get(), KeysetDeriver.class);
    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode(t.inputHex));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(t.derivedKeyParameters);
    assertThat(derivedKeyset.getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(idRequirement);
    assertThat(derivedKeyset.getAt(0).getKey().equalsKey(t.expectedKey)).isTrue();
  }
}
