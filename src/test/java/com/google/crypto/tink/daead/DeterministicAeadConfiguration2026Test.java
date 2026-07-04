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

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.ProtoParametersSerialization;
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
public class DeterministicAeadConfiguration2026Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, DeterministicAeadConfiguration2026::get);
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
                DeterministicAeadConfiguration2026.get(), DeterministicAead.class))
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

    Configuration config = DeterministicAeadConfiguration2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(config, DeterministicAead.class));
  }

  @Test
  public void createKey_aesSivParameters() throws Exception {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    Key key = DeterministicAeadConfiguration2026.get().createKey(parameters, 42);
    assertThat(key).isInstanceOf(AesSivKey.class);
    AesSivKey aesSivKey = (AesSivKey) key;
    assertThat(aesSivKey.getParameters()).isEqualTo(parameters);
    assertThat(aesSivKey.getIdRequirementOrNull()).isEqualTo(42);
  }

  @Test
  public void createKey_unrecognizedParameters_throws() throws Exception {
    Parameters parameters =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    Configuration config = DeterministicAeadConfiguration2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  private static interface DummyPrimitive {}

  @Test
  public void createPrimitive_unsupportedPrimitiveClass_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesSivProtoSerialization.register();
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(64))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = DeterministicAeadConfiguration2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(config, DummyPrimitive.class));
  }

  @Test
  public void createKey_aesSivParametersWithoutIdRequirement_works() throws Exception {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    Key key = DeterministicAeadConfiguration2026.get().createKey(parameters, null);
    assertThat(key).isInstanceOf(AesSivKey.class);
    AesSivKey aesSivKey = (AesSivKey) key;
    assertThat(aesSivKey.getParameters()).isEqualTo(parameters);
    assertThat(aesSivKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createKey_aesSivParametersWithIdRequirementButPassedNull_throws() throws Exception {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    Configuration config = DeterministicAeadConfiguration2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  @Test
  public void getOrNull_protoKeySerializer_serializeAndParseParameters() throws Exception {
    ProtoKeySerializer serializer =
        DeterministicAeadConfiguration2026.get().getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();

    ProtoParametersSerialization serializedParameters =
        serializer.serializeParameters(parameters);
    assertThat(serializer.parseParameters(serializedParameters)).isEqualTo(parameters);
  }

  @Test
  public void getOrNull_protoKeySerializer_serializeAndParseKey() throws Exception {
    ProtoKeySerializer serializer =
        DeterministicAeadConfiguration2026.get().getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(64))
            .build();

    ProtoKeySerialization serializedKey =
        serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    assertThat(
            serializer
                .parseKey(serializedKey, InsecureSecretKeyAccess.get())
                .equalsKey(key))
        .isTrue();
  }

  @Test
  public void getOrNull_unsupportedClass_returnsNull() throws Exception {
    assertThat(DeterministicAeadConfiguration2026.get().getOrNull(String.class)).isNull();
  }
}
