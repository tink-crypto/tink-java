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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.daead.subtle.AesSivDeterministicAead;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for DeterministicAead which run under FIPS mode.
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

  @Test
  public void deterministicAeadConfig2026() throws Exception {
    assertThat(DeterministicAeadConfig2026.get()).isNotNull();

    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesSivKey.builder()
                            .setParameters(params)
                            .setKeyBytes(
                                SecretBytes.copyFrom(new byte[64], InsecureSecretKeyAccess.get()))
                            .setIdRequirement(42)
                            .build())
                    .makePrimary())
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(params, DeterministicAeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> handle.getPrimitive(DeterministicAeadConfig2026.get(), DeterministicAead.class));
    } else {
      assertThat(KeysetHandle.generateNew(params, DeterministicAeadConfig2026.get())).isNotNull();
      assertThat(handle.getPrimitive(DeterministicAeadConfig2026.get(), DeterministicAead.class))
          .isNotNull();
    }
  }

  @Test
  public void aesSivConstructor() throws Exception {
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> new AesSiv(new byte[64]));
    } else {
      assertThat(new AesSiv(new byte[64])).isNotNull();
    }
  }

  @Test
  public void aesSivDeterministicAeadCreate() throws Exception {
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(new byte[64], InsecureSecretKeyAccess.get()))
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesSivDeterministicAead.create(key));
    } else {
      assertThat(AesSivDeterministicAead.create(key)).isNotNull();
    }
  }
}
