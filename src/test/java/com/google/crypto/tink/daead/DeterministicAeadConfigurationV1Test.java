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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivParameters.Variant;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class DeterministicAeadConfigurationV1Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, DeterministicAeadConfigurationV1::get);
  }

  @Test
  public void config_containsAesSivForDeterministicAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesSivProtoSerialization.register();
    AesSivParameters parameters =
        AesSivParameters.builder().setKeySizeBytes(64).setVariant(Variant.NO_PREFIX).build();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(64))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(
        keysetHandle.getPrimitive(
            DeterministicAeadConfigurationV1.get(), DeterministicAead.class))
        .isNotNull();
  }

  @Test
  public void config_disallowsNon64ByteKeyForAesSiv() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesSivProtoSerialization.register();
    AesSivParameters parameters =
        AesSivParameters.builder().setKeySizeBytes(32).setVariant(Variant.NO_PREFIX).build();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            keysetHandle.getPrimitive(
                DeterministicAeadConfigurationV1.get(), DeterministicAead.class));
  }
}
