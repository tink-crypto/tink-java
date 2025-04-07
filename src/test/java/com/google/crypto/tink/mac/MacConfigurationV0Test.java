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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.mac.internal.AesCmacProtoSerialization;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.proto.HashType;
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
public class MacConfigurationV0Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, MacConfigurationV0::get);
  }

  @Test
  public void config_containsHmacForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HmacProtoSerialization.register();
    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_containsHmacForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HmacProtoSerialization.register();
    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }

  @Test
  public void config_containsAesCmacForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class));
  }

  @Test
  public void config_containsAesCmacForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesCmacProtoSerialization.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class));
  }

  private final ByteString random32ByteKeyValue =
      ByteString.copyFrom(SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get()));

  @Test
  public void config_handlesHmacLegacyProtoKeyForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.HmacParams protoParams =
        com.google.crypto.tink.proto.HmacParams.newBuilder()
            .setTagSize(16)
            .setHash(HashType.SHA256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setParams(protoParams)
                .setKeyValue(random32ByteKeyValue)
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

    HmacProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_handlesAesCmacLegacyProtoKeyForMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.AesCmacParams protoParams =
        com.google.crypto.tink.proto.AesCmacParams.newBuilder().setTagSize(16).build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCmacKey",
            com.google.crypto.tink.proto.AesCmacKey.newBuilder()
                .setParams(protoParams)
                .setKeyValue(random32ByteKeyValue)
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

    AesCmacProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), Mac.class)).isNotNull();
  }

  @Test
  public void config_handlesHmacLegacyProtoKeyForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.HmacParams protoParams =
        com.google.crypto.tink.proto.HmacParams.newBuilder()
            .setTagSize(16)
            .setHash(HashType.SHA256)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            com.google.crypto.tink.proto.HmacKey.newBuilder()
                .setParams(protoParams)
                .setKeyValue(random32ByteKeyValue)
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

    HmacProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }

  @Test
  public void config_handlesAesCmacLegacyProtoKeyForChunkedMac() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.AesCmacParams protoParams =
        com.google.crypto.tink.proto.AesCmacParams.newBuilder().setTagSize(16).build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCmacKey",
            com.google.crypto.tink.proto.AesCmacKey.newBuilder()
                .setParams(protoParams)
                .setKeyValue(random32ByteKeyValue)
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

    AesCmacProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(MacConfigurationV0.get(), ChunkedMac.class)).isNotNull();
  }
}
