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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.internal.AesCtrHmacAeadProtoSerialization;
import com.google.crypto.tink.aead.internal.AesEaxProtoSerialization;
import com.google.crypto.tink.aead.internal.AesGcmProtoSerialization;
import com.google.crypto.tink.aead.internal.AesGcmSivProtoSerialization;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.aead.internal.XAesGcmProtoSerialization;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class AeadConfigurationV0Test {

  @BeforeClass
  public static void setUp() throws Exception {
    if (!Util.isAndroid()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, AeadConfigurationV0::get);
  }

  @Test
  public void config_containsAesCtrHmacAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesCtrHmacAeadProtoSerialization.register();

    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(12)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsAesGcmAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesGcmProtoSerialization.register();

    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsAesGcmSivAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesGcmSivProtoSerialization.register();

    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    if (Util.isAndroid() && Util.getAndroidApiLevel() < 30) {
      // Must fail because Android's AES-GCM-SIV Cipher is invalid prior to Android 30.
      assertThrows(
          GeneralSecurityException.class,
          () -> keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class));
      return;
    }
    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsAesEaxAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    AesEaxProtoSerialization.register();

    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesEaxParameters.Variant.TINK)
            .build();
    AesEaxKey key =
        AesEaxKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsChaCha20Poly1305Aead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    ChaCha20Poly1305ProtoSerialization.register();

    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsXChaCha20Poly1305Aead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    XChaCha20Poly1305ProtoSerialization.register();

    XChaCha20Poly1305Key key =
        XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_containsXAesGcmAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    XAesGcmProtoSerialization.register();

    XAesGcmKey key =
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 10),
            SecretBytes.randomBytes(32),
            42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  private final ByteString random32ByteKeyValue =
      ByteString.copyFrom(SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get()));

  @Test
  public void config_handlesAesCtrHmacLegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            com.google.crypto.tink.proto.AesCtrHmacAeadKey.newBuilder()
                .setAesCtrKey(
                    com.google.crypto.tink.proto.AesCtrKey.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                                .setIvSize(12)
                                .build())
                        .setKeyValue(random32ByteKeyValue)
                        .build())
                .setHmacKey(
                    com.google.crypto.tink.proto.HmacKey.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.HmacParams.newBuilder()
                                .setTagSize(16)
                                .setHash(HashType.SHA256)
                                .build())
                        .setKeyValue(random32ByteKeyValue)
                        .build())
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

    AesCtrHmacAeadProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  private final ByteString random24ByteKeyValue =
      ByteString.copyFrom(SecretBytes.randomBytes(24).toByteArray(InsecureSecretKeyAccess.get()));

  @Test
  public void config_disallows24ByteAesKeyForAesCtrHmacAeadWithLegacyKey() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            com.google.crypto.tink.proto.AesCtrHmacAeadKey.newBuilder()
                .setAesCtrKey(
                    com.google.crypto.tink.proto.AesCtrKey.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.AesCtrParams.newBuilder()
                                .setIvSize(12)
                                .build())
                        .setKeyValue(random24ByteKeyValue)
                        .build())
                .setHmacKey(
                    com.google.crypto.tink.proto.HmacKey.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.HmacParams.newBuilder()
                                .setTagSize(16)
                                .setHash(HashType.SHA256)
                                .build())
                        .setKeyValue(random32ByteKeyValue)
                        .build())
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

    AesCtrHmacAeadProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class));
  }

  @Test
  public void config_handlesAesGcmLegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesGcmKey",
            com.google.crypto.tink.proto.AesGcmKey.newBuilder()
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

    AesGcmProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_disallows24ByteAesKeyForAesGcmAeadWithLegacyKey() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesGcmKey",
            com.google.crypto.tink.proto.AesGcmKey.newBuilder()
                .setKeyValue(random24ByteKeyValue)
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

    AesGcmProtoSerialization.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class));
  }

  @Test
  public void config_handlesAesGcmSivLegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
            com.google.crypto.tink.proto.AesGcmSivKey.newBuilder()
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

    AesGcmSivProtoSerialization.register();

    if (Util.isAndroid() && Util.getAndroidApiLevel() < 30) {
      // Must fail because Android's AES-GCM-SIV Cipher is invalid prior to Android 30.
      assertThrows(
          GeneralSecurityException.class,
          () -> keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class));
      return;
    }
    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_handlesAesEaxLegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.AesEaxKey",
            com.google.crypto.tink.proto.AesEaxKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.AesEaxParams.newBuilder().setIvSize(16).build())
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

    AesEaxProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_handlesChaCha20Poly1305LegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
            com.google.crypto.tink.proto.ChaCha20Poly1305Key.newBuilder()
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

    ChaCha20Poly1305ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }

  @Test
  public void config_handlesXChaCha20Poly1305LegacyKeyForAead() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
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

    XChaCha20Poly1305ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(AeadConfigurationV0.get(), Aead.class)).isNotNull();
  }
}
