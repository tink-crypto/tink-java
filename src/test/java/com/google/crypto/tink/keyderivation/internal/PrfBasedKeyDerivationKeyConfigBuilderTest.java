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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerializer;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.subtle.AesGcmProtoSerialization;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.subtle.HmacProtoSerialization;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.subtle.HkdfPrfProtoSerialization;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfBasedKeyDerivationKeyConfigBuilderTest {

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @AccessesPartialKey
  private static Key createAesGcmKey(
      AesGcmParameters aesGcmParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return AesGcmKey.builder()
        .setParameters(aesGcmParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, aesGcmParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static Key createHmacKey(
      HmacParameters hmacParameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return HmacKey.builder()
        .setParameters(hmacParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, hmacParameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static HkdfPrfKey createHkdfPrfKey(
      HkdfPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("PRF Keys are not expected to have an id Requirement");
    }
    return HkdfPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @AccessesPartialKey
  private static PrfBasedKeyDerivationKey createPrfBasedKeyDerivationKey(
      PrfBasedKeyDerivationParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Parameters prfParameters = parameters.getPrfParameters();
    if (prfParameters instanceof HkdfPrfParameters) {
      HkdfPrfKey prfKey =
          createHkdfPrfKey((HkdfPrfParameters) prfParameters, /* idRequirement= */ null);
      return PrfBasedKeyDerivationKey.create(parameters, prfKey, idRequirement);
    }
    throw new GeneralSecurityException("Unsupported PRF parameters: " + prfParameters.getClass());
  }

  @AccessesPartialKey
  private static KeyDeriver createPrfBasedKeyDeriver(
      PrfBasedKeyDerivationKey key, PrfBasedKeyDerivationKeyConfig configForKey)
      throws GeneralSecurityException {
    return PrfBasedKeyDeriver.create(
        k -> {
          if (k instanceof HkdfPrfKey) {
            return HkdfStreamingPrf.create((HkdfPrfKey) k);
          }
          throw new GeneralSecurityException("Unsupported PRF key type: " + k.getClass());
        },
        configForKey::createKeyFromRandomness,
        key);
  }

  private static Configuration createFullConfiguration(
      PrfBasedKeyDerivationKeyConfig keyDerivationKeyConfig) throws GeneralSecurityException {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(
            KeysetDeriver.class, KeyDeriver.class, KeysetDeriverWrapper.WRAPPER::wrap)
        .addKeyCreator(
            PrfBasedKeyDerivationParameters.class,
            PrfBasedKeyDerivationKeyConfigBuilderTest::createPrfBasedKeyDerivationKey)
        .addPrimitiveConstructor(
            (PrfBasedKeyDerivationKey key) -> createPrfBasedKeyDeriver(key, keyDerivationKeyConfig),
            PrfBasedKeyDerivationKey.class,
            KeyDeriver.class)
        .addKeySerializer(
            PrfBasedKeyDerivationKey.class,
            (key, access) ->
                PrfBasedKeyDerivationKeyProtoSerialization.serializeKey(
                    key, access, keyDerivationKeyConfig.getConfiguration()))
        .addParametersSerializer(
            PrfBasedKeyDerivationParameters.class,
            parameters ->
                PrfBasedKeyDerivationKeyProtoSerialization.serializeParameters(
                    parameters, keyDerivationKeyConfig.getConfiguration()))
        .addKeyParser(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            (serialization, access) ->
                PrfBasedKeyDerivationKeyProtoSerialization.parseKey(
                    serialization, access, keyDerivationKeyConfig.getConfiguration()))
        .addParametersParser(
            "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
            serialization ->
                PrfBasedKeyDerivationKeyProtoSerialization.parseParameters(
                    serialization, keyDerivationKeyConfig.getConfiguration()))
        .build();
  }

  @Test
  public void build_empty_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig config = new PrfBasedKeyDerivationKeyConfigBuilder().build();
    assertThat(config).isNotNull();
    assertThat(config.getConfiguration()).isNotNull();
  }

  @Test
  public void addKeySerializer_twiceForSameClass_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey);
    assertThrows(
        IllegalArgumentException.class,
        () -> builder.addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey));
  }

  @Test
  public void addKeyParser_twiceForSameTypeUrl_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey));
  }

  @Test
  public void addParametersSerializer_twiceForSameClass_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters));
  }

  @Test
  public void addParametersParser_twiceForSameTypeUrl_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters));
  }

  @Test
  public void addKeyFromRandomness_twiceForSameClass_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            builder.addKeyFromRandomness(
                AesGcmParameters.class,
                PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey));
  }

  @Test
  public void createKeyFromRandomness_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig config =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey)
            .build();

    AesGcmParameters aesGcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    byte[] randomness = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    Key key =
        config.createKeyFromRandomness(
            aesGcmParams,
            new ByteArrayInputStream(randomness),
            /* idRequirement= */ null,
            InsecureSecretKeyAccess.get());
    assertThat(key.getParameters()).isEqualTo(aesGcmParams);
  }

  @Test
  public void createKeyFromRandomness_withIdRequirement_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig config =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey)
            .build();

    AesGcmParameters aesGcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();

    byte[] randomness = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    Key key =
        config.createKeyFromRandomness(
            aesGcmParams,
            new ByteArrayInputStream(randomness),
            /* idRequirement= */ 12345,
            InsecureSecretKeyAccess.get());
    assertThat(key.getParameters()).isEqualTo(aesGcmParams);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(12345);
  }

  @Test
  public void createKeyFromRandomness_unregisteredParameters_throws() throws Exception {
    PrfBasedKeyDerivationKeyConfig config = new PrfBasedKeyDerivationKeyConfigBuilder().build();

    AesGcmParameters aesGcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    byte[] randomness = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    assertThrows(
        GeneralSecurityException.class,
        () ->
            config.createKeyFromRandomness(
                aesGcmParams,
                new ByteArrayInputStream(randomness),
                /* idRequirement= */ null,
                InsecureSecretKeyAccess.get()));
  }

  @Test
  public void builderMutationAfterBuild_doesNotAffectPreviouslyBuiltConfig() throws Exception {
    PrfBasedKeyDerivationKeyConfigBuilder builder = new PrfBasedKeyDerivationKeyConfigBuilder();
    PrfBasedKeyDerivationKeyConfig config1 = builder.build();

    builder.addKeyFromRandomness(
        AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey);
    PrfBasedKeyDerivationKeyConfig config2 = builder.build();

    AesGcmParameters aesGcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    byte[] randomness = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    assertThrows(
        GeneralSecurityException.class,
        () ->
            config1.createKeyFromRandomness(
                aesGcmParams,
                new ByteArrayInputStream(randomness),
                /* idRequirement= */ null,
                InsecureSecretKeyAccess.get()));

    Key key =
        config2.createKeyFromRandomness(
            aesGcmParams,
            new ByteArrayInputStream(randomness),
            /* idRequirement= */ null,
            InsecureSecretKeyAccess.get());
    assertThat(key.getParameters()).isEqualTo(aesGcmParams);
  }

  @Test
  @AccessesPartialKey
  public void configuration_keyAndParametersSerializationAndParsing_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig keyConfig =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters)
            .build();

    Configuration config = keyConfig.getConfiguration();
    ProtoKeySerializer serializer = config.getOrNull(ProtoKeySerializer.class);
    assertThat(serializer).isNotNull();

    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();

    ProtoParametersSerialization protoParams = serializer.serializeParameters(parameters);
    Parameters parsedParams = serializer.parseParameters(protoParams);
    assertThat(parsedParams).isEqualTo(parameters);

    ProtoKeySerialization protoKey = serializer.serializeKey(key, InsecureSecretKeyAccess.get());
    Key parsedKey = serializer.parseKey(protoKey, InsecureSecretKeyAccess.get());
    assertThat(parsedKey.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void endToEnd_deriveKey_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig keyConfig =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters)
            .addParametersSerializer(
                AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.AesGcmKey",
                AesGcmProtoSerialization::parseParameters)
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey)
            .build();

    Configuration config = createFullConfiguration(keyConfig);

    HkdfPrfParameters prfParameters =
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
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfParameters)
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();

    KeysetHandle keysetHandle = KeysetHandle.generateNew(parameters, config);
    KeysetDeriver deriver = keysetHandle.getPrimitive(config, KeysetDeriver.class);
    KeysetHandle derivedKeysetHandle = deriver.deriveKeyset(new byte[] {1, 2, 3});

    Aead aead = derivedKeysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] plaintext = new byte[] {4, 5, 6};
    byte[] associatedData = new byte[] {7, 8, 9};
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void endToEnd_keysetSerializationAndParsing_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig keyConfig =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters)
            .addParametersSerializer(
                AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.AesGcmKey",
                AesGcmProtoSerialization::parseParameters)
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey)
            .build();

    Configuration config = createFullConfiguration(keyConfig);

    HkdfPrfParameters prfParameters =
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
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfParameters)
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();

    KeysetHandle keysetHandle = KeysetHandle.generateNew(parameters, config);
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsedKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get(), config);

    assertThat(parsedKeysetHandle.size()).isEqualTo(keysetHandle.size());
    assertThat(parsedKeysetHandle.getAt(0).getKey().getParameters())
        .isEqualTo(keysetHandle.getAt(0).getKey().getParameters());
  }

  @Test
  public void endToEnd_parametersSerializationAndParsing_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig keyConfig =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters)
            .addParametersSerializer(
                AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.AesGcmKey",
                AesGcmProtoSerialization::parseParameters)
            .build();

    Configuration config = createFullConfiguration(keyConfig);

    HkdfPrfParameters prfParameters =
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
    PrfBasedKeyDerivationParameters parameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfParameters)
            .setDerivedKeyParameters(derivedKeyParameters)
            .build();

    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void multipleKeyFromRandomness_works() throws Exception {
    PrfBasedKeyDerivationKeyConfig keyConfig =
        new PrfBasedKeyDerivationKeyConfigBuilder()
            .addKeySerializer(HkdfPrfKey.class, HkdfPrfProtoSerialization::serializeKey)
            .addParametersSerializer(
                HkdfPrfParameters.class, HkdfPrfProtoSerialization::serializeParameters)
            .addKeyParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseKey)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
                HkdfPrfProtoSerialization::parseParameters)
            .addParametersSerializer(
                AesGcmParameters.class, AesGcmProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.AesGcmKey",
                AesGcmProtoSerialization::parseParameters)
            .addKeyFromRandomness(
                AesGcmParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createAesGcmKey)
            .addParametersSerializer(
                HmacParameters.class, HmacProtoSerialization::serializeParameters)
            .addParametersParser(
                "type.googleapis.com/google.crypto.tink.HmacKey",
                HmacProtoSerialization::parseParameters)
            .addKeyFromRandomness(
                HmacParameters.class, PrfBasedKeyDerivationKeyConfigBuilderTest::createHmacKey)
            .build();

    Configuration config = createFullConfiguration(keyConfig);

    HkdfPrfParameters prfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();

    // 1. Derive AesGcm
    AesGcmParameters aesGcmParams =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters aesGcmDerivationParams =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfParameters)
            .setDerivedKeyParameters(aesGcmParams)
            .build();
    KeysetHandle aesGcmHandle = KeysetHandle.generateNew(aesGcmDerivationParams, config);
    KeysetDeriver aesGcmDeriver = aesGcmHandle.getPrimitive(config, KeysetDeriver.class);
    KeysetHandle derivedAesGcm = aesGcmDeriver.deriveKeyset(new byte[] {1, 2, 3});
    assertThat(derivedAesGcm.getAt(0).getKey().getParameters()).isEqualTo(aesGcmParams);

    // 2. Derive Hmac
    HmacParameters hmacParams =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters hmacDerivationParams =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(prfParameters)
            .setDerivedKeyParameters(hmacParams)
            .build();
    KeysetHandle hmacHandle = KeysetHandle.generateNew(hmacDerivationParams, config);
    KeysetDeriver hmacDeriver = hmacHandle.getPrimitive(config, KeysetDeriver.class);
    KeysetHandle derivedHmac = hmacDeriver.deriveKeyset(new byte[] {1, 2, 3});
    assertThat(derivedHmac.getAt(0).getKey().getParameters()).isEqualTo(hmacParams);
  }
}
