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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.internal.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.internal.ChunkedHmacImpl;
import com.google.crypto.tink.mac.internal.WrappedChunkedMac;
import com.google.crypto.tink.mac.internal.WrappedMac;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ProtoBasedConfigurationBuilderTest {
  @Test
  public void testBuildEmpty_works() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    assertThat(config).isNotNull();
  }

  @Test
  public void testCreateKey_withoutIdRequirement_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    // Create without id Requirement works
    Key createdKey = config.createKey(XChaCha20Poly1305Parameters.create(), null);
    assertThat(createdKey.getParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());

    // Create with id Requirement works
    Parameters tinkParams =
        XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
    createdKey = config.createKey(tinkParams, 13996);
    assertThat(createdKey.getParameters()).isEqualTo(tinkParams);
    assertThat(createdKey.getIdRequirementOrNull()).isEqualTo(13996);

    // If idRequirement is wrong we throw.
    assertThrows(
        GeneralSecurityException.class,
        () -> config.createKey(XChaCha20Poly1305Parameters.create(), 1234));
    assertThrows(GeneralSecurityException.class, () -> config.createKey(tinkParams, null));
  }

  @Test
  public void testAddKeyCreator_twiceForSameParameters_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id)));
  }

  @Test
  public void testDispatchToMultipleCreators_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .addKeyCreator(
                ChaCha20Poly1305Parameters.class,
                (p, id) ->
                    ChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    Key creator1Key = config.createKey(XChaCha20Poly1305Parameters.create(), null);
    assertThat(creator1Key.getParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());

    Key creator2Key = config.createKey(ChaCha20Poly1305Parameters.create(), null);
    assertThat(creator2Key.getParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
  }

  @Test
  public void testCreateKey_withUnregisteredParameters_throws() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();

    assertThrows(
        GeneralSecurityException.class,
        () -> config.createKey(ChaCha20Poly1305Parameters.create(), null));
  }

  @Test
  public void testCreatePrimitive_actualMac_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
            .build();

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

    Mac mac = keysetHandle.getPrimitive(config, Mac.class);
    assertThat(mac).isNotNull();

    byte[] data = new byte[0];
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data); // Should not throw
  }

  @Test
  public void testRegisterPrimitiveConstructor_twice_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class);

    assertThrows(
        IllegalArgumentException.class,
        () -> builder.addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class));
  }

  @Test
  public void testRegisterPrimitiveWrapper_twice_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create);

    assertThrows(
        IllegalArgumentException.class,
        () -> builder.addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create));
  }

  @Test
  public void testCreatePrimitive_multiplePrimitives_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
            .addPrimitiveConstructor(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class)
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
            .addPrimitiveWrapper(ChunkedMac.class, ChunkedMac.class, WrappedChunkedMac::create)
            .build();

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

    // Verify we can get Mac
    Mac mac = keysetHandle.getPrimitive(config, Mac.class);
    assertThat(mac).isNotNull();
    byte[] data = new byte[0];
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data); // Should not throw

    // Verify we can get ChunkedMac
    ChunkedMac chunkedMac = keysetHandle.getPrimitive(config, ChunkedMac.class);
    assertThat(chunkedMac).isNotNull();
  }

  @Test
  public void testCreatePrimitive_multipleKeyTypes_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
            .addPrimitiveConstructor(PrfMac::create, AesCmacKey.class, Mac.class)
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
            .build();

    // 1. Test with HmacKey
    HmacParameters hmacParameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(hmacParameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle hmacKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hmacKey).withRandomId().makePrimary())
            .build();

    Mac hmac = hmacKeysetHandle.getPrimitive(config, Mac.class);
    assertThat(hmac).isNotNull();
    byte[] tag1 = hmac.computeMac(new byte[0]);
    hmac.verifyMac(tag1, new byte[0]);

    // 2. Test with AesCmacKey
    AesCmacParameters aesCmacParameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey aesCmacKey =
        AesCmacKey.builder()
            .setParameters(aesCmacParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle aesCmacKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesCmacKey).withRandomId().makePrimary())
            .build();

    Mac aesCmac = aesCmacKeysetHandle.getPrimitive(config, Mac.class);
    assertThat(aesCmac).isNotNull();
    byte[] tag2 = aesCmac.computeMac(new byte[0]);
    aesCmac.verifyMac(tag2, new byte[0]);
  }

  @Test
  public void testParametersParsingSerialization_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters)
            .build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    ChaCha20Poly1305Parameters parameters =
        ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);
    Parameters reParsed = serializer.parseParameters(serializer.serializeParameters(parameters));

    assertThat(reParsed).isEqualTo(parameters);
  }

  @Test
  public void testKeySerialization_works() throws Exception {
    Configuration config =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey)
            .build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    byte[] keyMaterial = SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get());
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()),
            /* idRequirement= */ 123);

    ProtoKeySerialization serialization =
        serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    Key reParsed = serializer.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(key.equalsKey(reParsed)).isEqualTo(true);
  }

  @Test
  public void testAddKeySerializer_twiceForSameClass_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey));
  }

  @Test
  public void testAddParametersSerializer_twiceForSameClass_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters));
  }

  @Test
  public void testAddKeyParser_twiceForSameTypeUrl_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey));
  }

  @Test
  public void testAddParametersParser_twiceForSameTypeUrl_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters));
  }

  @Test
  public void testSerializeKey_unregisteredKey_throws() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.randomBytes(32),
            /* idRequirement= */ 123);
    assertThrows(
        GeneralSecurityException.class,
        () -> serializer.serializeKey(key, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void testSerializeParameters_unregisteredParameters_throws() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    ChaCha20Poly1305Parameters parameters =
        ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);
    assertThrows(GeneralSecurityException.class, () -> serializer.serializeParameters(parameters));
  }

  @Test
  public void testParseKey_unregisteredTypeUrl_throws() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
            ByteString.EMPTY,
            ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            ProtoKeySerialization.OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThrows(
        GeneralSecurityException.class,
        () -> serializer.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void testParseParameters_unregisteredTypeUrl_throws() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
            ProtoKeySerialization.OutputPrefixType.RAW,
            ByteString.EMPTY);
    assertThrows(GeneralSecurityException.class, () -> serializer.parseParameters(serialization));
  }

  @Test
  public void testGetOrNull_unknownClass_returnsNull() throws Exception {
    Configuration config = new ProtoBasedConfigurationBuilder().build();
    assertThat(config.getOrNull(String.class)).isNull();
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesKeyCreators() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                ChaCha20Poly1305Parameters.class,
                (p, id) ->
                    ChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id));
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                XChaCha20Poly1305Parameters.class,
                (p, id) ->
                    XChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    Key chaChaKey = config.createKey(ChaCha20Poly1305Parameters.create(), null);
    assertThat(chaChaKey.getParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
    Key xChaChaKey = config.createKey(XChaCha20Poly1305Parameters.create(), null);
    assertThat(xChaChaKey.getParameters()).isEqualTo(XChaCha20Poly1305Parameters.create());
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesPrimitiveConstructors() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(ChunkedHmacImpl::new, HmacKey.class, ChunkedMac.class)
            .addPrimitiveWrapper(ChunkedMac.class, ChunkedMac.class, WrappedChunkedMac::create)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hmacKey).withRandomId().makePrimary())
            .build();

    Mac mac = keysetHandle.getPrimitive(config, Mac.class);
    assertThat(mac).isNotNull();
    ChunkedMac chunkedMac = keysetHandle.getPrimitive(config, ChunkedMac.class);
    assertThat(chunkedMac).isNotNull();
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesPrimitiveWrappers() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hmacKey).withRandomId().makePrimary())
            .build();

    Mac mac = keysetHandle.getPrimitive(config, Mac.class);
    assertThat(mac).isNotNull();
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesKeySerializers() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    byte[] keyMaterial = SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get());
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()),
            /* idRequirement= */ 123);

    ProtoKeySerialization serialization =
        serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    Key reParsed = serializer.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(key.equalsKey(reParsed)).isTrue();
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesKeyParsers() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    byte[] keyMaterial = SecretBytes.randomBytes(32).toByteArray(InsecureSecretKeyAccess.get());
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK,
            SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()),
            /* idRequirement= */ 123);

    ProtoKeySerialization serialization =
        serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    Key reParsed = serializer.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(key.equalsKey(reParsed)).isTrue();
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesParametersSerializers() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();
    ChaCha20Poly1305Parameters params =
        ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);
    Parameters reParsedParams = serializer.parseParameters(serializer.serializeParameters(params));
    assertThat(reParsedParams).isEqualTo(params);
  }

  @Test
  public void testMergeProtoBasedConfiguration_mergesParametersParsers() throws Exception {
    ProtoBasedConfigurationBuilder builder =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters);
    Configuration otherConfig =
        new ProtoBasedConfigurationBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters)
            .build();

    Configuration config = builder.mergeProtoBasedConfiguration(otherConfig).build();

    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();
    ChaCha20Poly1305Parameters params =
        ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);
    Parameters reParsedParams = serializer.parseParameters(serializer.serializeParameters(params));
    assertThat(reParsedParams).isEqualTo(params);
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicateKeyCreator_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                ChaCha20Poly1305Parameters.class,
                (p, id) ->
                    ChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id));
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addKeyCreator(
                ChaCha20Poly1305Parameters.class,
                (p, id) ->
                    ChaCha20Poly1305Key.create(p.getVariant(), SecretBytes.randomBytes(32), id))
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicatePrimitiveConstructor_throws()
      throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveConstructor(PrfMac::create, HmacKey.class, Mac.class)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicatePrimitiveWrapper_throws()
      throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addPrimitiveWrapper(Mac.class, Mac.class, WrappedMac::create)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicateKeySerializer_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addKeySerializer(
                ChaCha20Poly1305Key.class, ChaCha20Poly1305ProtoSerialization::serializeKey)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicateParametersSerializer_throws()
      throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addParametersSerializer(
                ChaCha20Poly1305Parameters.class,
                ChaCha20Poly1305ProtoSerialization::serializeParameters)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicateKeyParser_throws() throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseKey)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_duplicateParametersParser_throws()
      throws Exception {
    ProtoBasedConfigurationBuilder builder1 =
        new ProtoBasedConfigurationBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters);
    Configuration config2 =
        new ProtoBasedConfigurationBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
                ChaCha20Poly1305ProtoSerialization::parseParameters)
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> builder1.mergeProtoBasedConfiguration(config2));
  }

  @Test
  public void testMergeProtoBasedConfiguration_nonProtoBasedConfiguration_throws()
      throws Exception {
    ProtoBasedConfigurationBuilder builder = new ProtoBasedConfigurationBuilder();
    Configuration otherConfig = RegistryConfiguration.get();

    assertThrows(
        IllegalArgumentException.class, () -> builder.mergeProtoBasedConfiguration(otherConfig));
  }
}
