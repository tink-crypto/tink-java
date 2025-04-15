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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.prf.internal.AesCmacPrfProtoSerialization;
import com.google.crypto.tink.prf.internal.HkdfPrfProtoSerialization;
import com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization;
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
public class PrfConfigurationV0Test {
  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, PrfConfigurationV0::get);
  }

  @Test
  public void config_containsHmacPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HmacPrfProtoSerialization.register();

    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HmacPrfParameters.HashType.SHA512)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_containsHkdfPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_containsAesCmacPrf() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesCmacPrfProtoSerialization.register();

    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void wrongAesCmacPrfKeySize_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesCmacPrfProtoSerialization.register();

    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(16), SecretBytes.randomBytes(16));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }

  @Test
  public void wrongHkdfPrfKeySize_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(16)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }

  @Test
  public void wrongHkdfPrfHashFunction_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    HkdfPrfProtoSerialization.register();

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA1)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }

  private final ByteString random32ByteKeyValue =
      ByteString.copyFrom(SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get()));

  @Test
  public void config_handlesHmacPrfLegacyKeyForPrfSet() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HmacPrfKey",
            com.google.crypto.tink.proto.HmacPrfKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HmacPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
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

    HmacPrfProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  private static final String HKDF_PRF_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

  @Test
  public void config_handlesHkdfPrfLegacyKeyForPrfSet() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            HKDF_PRF_KEY_TYPE_URL,
            com.google.crypto.tink.proto.HkdfPrfKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HkdfPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
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

    HkdfPrfProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_disallowsSmallHkdfPrfKeyForPrfSetWithLegacyKey() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            HKDF_PRF_KEY_TYPE_URL,
            com.google.crypto.tink.proto.HkdfPrfKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HkdfPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                        .build())
                .setKeyValue(
                    ByteString.copyFrom(
                        SecretBytes.randomBytes(24).toByteArray(InsecureSecretKeyAccess.get())))
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

    HkdfPrfProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }

  @Test
  public void config_disallowsNonSha256NonSha512HkdfPrfHashTypeForPrfSetWithLegacyKey()
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            HKDF_PRF_KEY_TYPE_URL,
            com.google.crypto.tink.proto.HkdfPrfKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.HkdfPrfParams.newBuilder()
                        .setHash(com.google.crypto.tink.proto.HashType.SHA1)
                        .build())
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

    HkdfPrfProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }

  private static final String AES_CMAC_PRF_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

  @Test
  public void config_handlesAesCmacPrfLegacyKeyForPrfSet() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            AES_CMAC_PRF_KEY_TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
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

    AesCmacPrfProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class)).isNotNull();
  }

  @Test
  public void config_disallows16ByteAesCmacPrfKeyForPrfSetWithLegacyKey() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            AES_CMAC_PRF_KEY_TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setKeyValue(
                    ByteString.copyFrom(
                        SecretBytes.randomBytes(16).toByteArray(InsecureSecretKeyAccess.get())))
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

    AesCmacPrfProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfigurationV0.get(), PrfSet.class));
  }
}
