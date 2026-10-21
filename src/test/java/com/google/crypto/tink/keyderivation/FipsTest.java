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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.keyderivation.internal.PrfBasedKeyDeriver;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KeyDerivation which run under FIPS mode.
 *
 * <p>We test this by tagging the test with "fips" which runs it under two build configurations:
 *
 * <ul>
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=False}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 * </ul>
 */
@RunWith(JUnit4.class)
public final class FipsTest {

  private static PrfBasedKeyDerivationParameters createParameters()
      throws GeneralSecurityException {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    return PrfBasedKeyDerivationParameters.builder()
        .setPrfParameters(hkdfPrfParameters)
        .setDerivedKeyParameters(derivedKeyParameters)
        .build();
  }

  @AccessesPartialKey
  private static PrfBasedKeyDerivationKey createKey(PrfBasedKeyDerivationParameters parameters)
      throws GeneralSecurityException {
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters((HkdfPrfParameters) parameters.getPrfParameters())
            .setKeyBytes(SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()))
            .build();
    return PrfBasedKeyDerivationKey.create(parameters, prfKey, /* idRequirement= */ 123);
  }

  @AccessesPartialKey
  private static Key createKeyFromRandomnessForAesGcm(
      Parameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    AesGcmParameters aesGcmParameters = (AesGcmParameters) parameters;
    return AesGcmKey.builder()
        .setParameters(aesGcmParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, aesGcmParameters.getKeySizeBytes(), access))
        .build();
  }

  @Test
  public void keyDerivationConfig2026() throws Exception {
    assertThat(KeyDerivationConfig2026.get()).isNotNull();

    PrfBasedKeyDerivationParameters params = createParameters();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(createKey(params)).withFixedId(123).makePrimary())
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(params, KeyDerivationConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> handle.getPrimitive(KeyDerivationConfig2026.get(), KeysetDeriver.class));
    } else {
      assertThat(KeysetHandle.generateNew(params, KeyDerivationConfig2026.get())).isNotNull();
      assertThat(handle.getPrimitive(KeyDerivationConfig2026.get(), KeysetDeriver.class))
          .isNotNull();
    }
  }

  @Test
  public void prfBasedKeyDeriverCreate() throws Exception {
    PrfBasedKeyDerivationKey key = createKey(createParameters());
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () ->
              PrfBasedKeyDeriver.create(
                  k -> HkdfStreamingPrf.create((HkdfPrfKey) k),
                  FipsTest::createKeyFromRandomnessForAesGcm,
                  key));
    } else {
      assertThat(
              PrfBasedKeyDeriver.create(
                  k -> HkdfStreamingPrf.create((HkdfPrfKey) k),
                  FipsTest::createKeyFromRandomnessForAesGcm,
                  key))
          .isNotNull();
    }
  }
}
