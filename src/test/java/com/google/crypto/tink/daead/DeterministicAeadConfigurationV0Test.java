// Copyright 2024 Google LLC
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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivParameters.Variant;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class DeterministicAeadConfigurationV0Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, DeterministicAeadConfigurationV0::get);
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
                DeterministicAeadConfigurationV0.get(), DeterministicAead.class))
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
                DeterministicAeadConfigurationV0.get(), DeterministicAead.class));
  }

  @Test
  public void config_handlesAesSivLegacyKeyForDeterministicAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesSivKey",
            com.google.crypto.tink.proto.AesSivKey.newBuilder()
                .setKeyValue(
                    ByteString.copyFrom(
                        SecretBytes.randomBytes(64).toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    AesSivProtoSerialization.register();

    assertThat(
            keysetHandle.getPrimitive(
                DeterministicAeadConfigurationV0.get(), DeterministicAead.class))
        .isNotNull();
  }

  @Test
  public void config_disallows32ByteAesSivKeyForDeterministicAeadWithLegacyKey() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesSivKey",
            com.google.crypto.tink.proto.AesSivKey.newBuilder()
                .setKeyValue(
                    ByteString.copyFrom(
                        SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    AesSivProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            keysetHandle.getPrimitive(
                DeterministicAeadConfigurationV0.get(), DeterministicAead.class));
  }
}
