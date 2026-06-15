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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoConversions;
import com.google.crypto.tink.proto.CompositeMlDsaClassicalAlgorithm;
import com.google.crypto.tink.proto.CompositeMlDsaKeyFormat;
import com.google.crypto.tink.proto.CompositeMlDsaParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.MlDsaInstance;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.CompositeMlDsaPublicKey;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.SignaturePrivateKey;
import com.google.crypto.tink.signature.SignaturePublicKey;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link CompositeMlDsaPrivateKey} and {@link
 * CompositeMlDsaPublicKey} objects and {@link CompositeMlDsaParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class CompositeMlDsaProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey";

  private static final MutableSerializationRegistry SERIALIZATION_REGISTRY =
      createSerializationRegistry();

  private static MutableSerializationRegistry createSerializationRegistry() {
    try {
      MutableSerializationRegistry registry = new MutableSerializationRegistry();
      MlDsaProtoSerialization.register(registry);
      Ed25519ProtoSerialization.register(registry);
      RsaSsaPkcs1ProtoSerialization.register(registry);
      RsaSsaPssProtoSerialization.register(registry);
      EcdsaProtoSerialization.register(registry);
      return registry;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Could not create serialization registry", e);
    }
  }

  private static final ParametersSerializer<CompositeMlDsaParameters>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              CompositeMlDsaProtoSerialization::serializeParameters,
              CompositeMlDsaParameters.class);

  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(CompositeMlDsaProtoSerialization::parseParameters, PRIVATE_TYPE_URL);

  private static final KeySerializer<CompositeMlDsaPublicKey> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(
          CompositeMlDsaProtoSerialization::serializePublicKey, CompositeMlDsaPublicKey.class);

  private static final KeyParser PUBLIC_KEY_PARSER =
      KeyParser.create(CompositeMlDsaProtoSerialization::parsePublicKey, PUBLIC_TYPE_URL);

  private static final KeySerializer<CompositeMlDsaPrivateKey> PRIVATE_KEY_SERIALIZER =
      KeySerializer.create(
          CompositeMlDsaProtoSerialization::serializePrivateKey, CompositeMlDsaPrivateKey.class);

  private static final KeyParser PRIVATE_KEY_PARSER =
      KeyParser.create(CompositeMlDsaProtoSerialization::parsePrivateKey, PRIVATE_TYPE_URL);

  private static OutputPrefixType toOutputPrefixType(CompositeMlDsaParameters.Variant variant)
      throws GeneralSecurityException {
    if (variant == CompositeMlDsaParameters.Variant.NO_PREFIX) {
      return OutputPrefixType.RAW;
    }
    if (variant == CompositeMlDsaParameters.Variant.TINK) {
      return OutputPrefixType.TINK;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static CompositeMlDsaParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType.equals(OutputPrefixType.RAW)) {
      return CompositeMlDsaParameters.Variant.NO_PREFIX;
    }
    if (outputPrefixType.equals(OutputPrefixType.TINK)) {
      return CompositeMlDsaParameters.Variant.TINK;
    }
    throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
  }

  private static final EnumTypeProtoConverter<MlDsaInstance, CompositeMlDsaParameters.MlDsaInstance>
      INSTANCE_CONVERTER =
          EnumTypeProtoConverter.<MlDsaInstance, CompositeMlDsaParameters.MlDsaInstance>builder()
              .add(MlDsaInstance.ML_DSA_65, CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
              .add(MlDsaInstance.ML_DSA_87, CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
              .build();

  private static final EnumTypeProtoConverter<
          CompositeMlDsaClassicalAlgorithm, CompositeMlDsaParameters.ClassicalAlgorithm>
      CLASSICAL_ALGORITHM_CONVERTER =
          EnumTypeProtoConverter
              .<CompositeMlDsaClassicalAlgorithm, CompositeMlDsaParameters.ClassicalAlgorithm>
                  builder()
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519,
                  CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ECDSA_P256,
                  CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P256)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ECDSA_P384,
                  CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P384)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ECDSA_P521,
                  CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P521)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_RSA3072_PSS,
                  CompositeMlDsaParameters.ClassicalAlgorithm.RSA3072_PSS)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_RSA4096_PSS,
                  CompositeMlDsaParameters.ClassicalAlgorithm.RSA4096_PSS)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_RSA3072_PKCS1,
                  CompositeMlDsaParameters.ClassicalAlgorithm.RSA3072_PKCS1)
              .add(
                  CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_RSA4096_PKCS1,
                  CompositeMlDsaParameters.ClassicalAlgorithm.RSA4096_PKCS1)
              .build();

  /**
   * Registers previously defined parser/serializer objects into a global, mutable registry.
   * Registration is public to enable custom configurations.
   */
  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  /** Registers previously defined parser/serializer objects into a given registry. */
  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registry.registerKeyParser(PUBLIC_KEY_PARSER);
    registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registry.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private static CompositeMlDsaParams getProtoParams(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    return CompositeMlDsaParams.newBuilder()
        .setMlDsaInstance(INSTANCE_CONVERTER.toProtoEnum(parameters.getMlDsaInstance()))
        .setClassicalAlgorithm(
            CLASSICAL_ALGORITHM_CONVERTER.toProtoEnum(parameters.getClassicalAlgorithm()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(
      CompositeMlDsaParameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL,
        toOutputPrefixType(parameters.getVariant()),
        CompositeMlDsaKeyFormat.newBuilder()
            .setParams(getProtoParams(parameters))
            .setVersion(0)
            .build()
            .toByteString());
  }

  private static ProtoKeySerialization serializePublicKey(
      CompositeMlDsaPublicKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    ProtoKeySerialization mlDsaKeySerialization =
        SERIALIZATION_REGISTRY.serializeKey(key.getMlDsaPublicKey(), /* access= */ null);
    if (!mlDsaKeySerialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException("Require raw output prefix for ML-DSA public key.");
    }
    if (mlDsaKeySerialization.getIdRequirementOrNull() != null) {
      throw new GeneralSecurityException("ML-DSA public key cannot have ID requirement.");
    }
    KeyData mlDsaKeyData =
        KeyData.newBuilder()
            .setTypeUrl(mlDsaKeySerialization.getTypeUrl())
            .setKeyMaterialType(
                ProtoConversions.toProto(mlDsaKeySerialization.getKeyMaterialType()))
            .setValue(mlDsaKeySerialization.getValue())
            .build();

    ProtoKeySerialization classicalKeySerialization =
        SERIALIZATION_REGISTRY.serializeKey(key.getClassicalPublicKey(), /* access= */ null);
    if (!classicalKeySerialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException("Require raw output prefix for classical public key.");
    }
    if (classicalKeySerialization.getIdRequirementOrNull() != null) {
      throw new GeneralSecurityException("Classical public key cannot have ID requirement.");
    }
    KeyData classicalKeyData =
        KeyData.newBuilder()
            .setTypeUrl(classicalKeySerialization.getTypeUrl())
            .setKeyMaterialType(
                ProtoConversions.toProto(classicalKeySerialization.getKeyMaterialType()))
            .setValue(classicalKeySerialization.getValue())
            .build();

    com.google.crypto.tink.proto.CompositeMlDsaPublicKey protoKey =
        com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setParams(getProtoParams(key.getParameters()))
            .setMlDsaPublicKey(mlDsaKeyData)
            .setClassicalPublicKey(classicalKeyData)
            .build();

    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        protoKey.toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ProtoKeySerialization serializePrivateKey(
      CompositeMlDsaPrivateKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    SecretKeyAccess.requireAccess(access);

    ProtoKeySerialization mlDsaKeySerialization =
        SERIALIZATION_REGISTRY.serializeKey(key.getMlDsaPrivateKey(), access);
    if (!mlDsaKeySerialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException("Require raw output prefix for ML-DSA private key.");
    }
    if (mlDsaKeySerialization.getIdRequirementOrNull() != null) {
      throw new GeneralSecurityException("ML-DSA private key cannot have ID requirement.");
    }
    KeyData mlDsaKeyData =
        KeyData.newBuilder()
            .setTypeUrl(mlDsaKeySerialization.getTypeUrl())
            .setKeyMaterialType(
                ProtoConversions.toProto(mlDsaKeySerialization.getKeyMaterialType()))
            .setValue(mlDsaKeySerialization.getValue())
            .build();

    ProtoKeySerialization classicalKeySerialization =
        SERIALIZATION_REGISTRY.serializeKey(key.getClassicalPrivateKey(), access);
    if (!classicalKeySerialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException("Require raw output prefix for classical private key.");
    }
    if (classicalKeySerialization.getIdRequirementOrNull() != null) {
      throw new GeneralSecurityException("Classical private key cannot have ID requirement.");
    }
    KeyData classicalKeyData =
        KeyData.newBuilder()
            .setTypeUrl(classicalKeySerialization.getTypeUrl())
            .setKeyMaterialType(
                ProtoConversions.toProto(classicalKeySerialization.getKeyMaterialType()))
            .setValue(classicalKeySerialization.getValue())
            .build();

    com.google.crypto.tink.proto.CompositeMlDsaPrivateKey protoKey =
        com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
            .setVersion(0)
            .setParams(getProtoParams(key.getParameters()))
            .setMlDsaPrivateKey(mlDsaKeyData)
            .setClassicalPrivateKey(classicalKeyData)
            .build();

    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        protoKey.toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static CompositeMlDsaParameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to CompositeMlDsaProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    CompositeMlDsaKeyFormat format;
    try {
      format =
          CompositeMlDsaKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing CompositeMlDsaParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted for Composite ML-DSA.");
    }
    return CompositeMlDsaParameters.builder()
        .setMlDsaInstance(INSTANCE_CONVERTER.fromProtoEnum(format.getParams().getMlDsaInstance()))
        .setClassicalAlgorithm(
            CLASSICAL_ALGORITHM_CONVERTER.fromProtoEnum(format.getParams().getClassicalAlgorithm()))
        .setVariant(toVariant(serialization.getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static CompositeMlDsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to CompositeMlDsaProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    if (!serialization.getKeyMaterialType().equals(KeyMaterialType.ASYMMETRIC_PUBLIC)) {
      throw new GeneralSecurityException(
          "Wrong KeyMaterialType for CompositeMlDsaPublicKey: "
              + serialization.getKeyMaterialType());
    }
    try {
      com.google.crypto.tink.proto.CompositeMlDsaPublicKey protoKey =
          com.google.crypto.tink.proto.CompositeMlDsaPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      CompositeMlDsaParameters parameters =
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(
                  INSTANCE_CONVERTER.fromProtoEnum(protoKey.getParams().getMlDsaInstance()))
              .setClassicalAlgorithm(
                  CLASSICAL_ALGORITHM_CONVERTER.fromProtoEnum(
                      protoKey.getParams().getClassicalAlgorithm()))
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();

      ProtoKeySerialization mlDsaKeySerialization =
          ProtoKeySerialization.create(
              protoKey.getMlDsaPublicKey().getTypeUrl(),
              protoKey.getMlDsaPublicKey().getValue(),
              ProtoConversions.fromProto(protoKey.getMlDsaPublicKey().getKeyMaterialType()),
              OutputPrefixType.RAW,
              /* idRequirement= */ null);
      Key parsedMlDsaKey =
          SERIALIZATION_REGISTRY.parseKey(mlDsaKeySerialization, /* access= */ null);
      if (!(parsedMlDsaKey instanceof MlDsaPublicKey)) {
        throw new GeneralSecurityException("Parsed ML-DSA key is not an MlDsaPublicKey");
      }

      ProtoKeySerialization classicalKeySerialization =
          ProtoKeySerialization.create(
              protoKey.getClassicalPublicKey().getTypeUrl(),
              protoKey.getClassicalPublicKey().getValue(),
              ProtoConversions.fromProto(protoKey.getClassicalPublicKey().getKeyMaterialType()),
              OutputPrefixType.RAW,
              /* idRequirement= */ null);
      Key parsedClassicalKey =
          SERIALIZATION_REGISTRY.parseKey(classicalKeySerialization, /* access= */ null);
      if (!(parsedClassicalKey instanceof SignaturePublicKey)) {
        throw new GeneralSecurityException("Parsed classical key is not a SignaturePublicKey");
      }

      CompositeMlDsaPublicKey.Builder builder =
          CompositeMlDsaPublicKey.builder()
              .setParameters(parameters)
              .setMlDsaPublicKey((MlDsaPublicKey) parsedMlDsaKey)
              .setClassicalPublicKey((SignaturePublicKey) parsedClassicalKey);
      if (serialization.getIdRequirementOrNull() != null) {
        builder.setIdRequirement(serialization.getIdRequirementOrNull());
      }
      return builder.build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing CompositeMlDsaPublicKey failed: ", e);
    }
  }

  @SuppressWarnings("UnusedException") // Prevents leaking key material
  private static CompositeMlDsaPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to CompositeMlDsaProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    if (!serialization.getKeyMaterialType().equals(KeyMaterialType.ASYMMETRIC_PRIVATE)) {
      throw new GeneralSecurityException(
          "Wrong KeyMaterialType for CompositeMlDsaPrivateKey: "
              + serialization.getKeyMaterialType());
    }
    SecretKeyAccess.requireAccess(access);

    try {
      com.google.crypto.tink.proto.CompositeMlDsaPrivateKey protoKey =
          com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      CompositeMlDsaParameters parameters =
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(
                  INSTANCE_CONVERTER.fromProtoEnum(protoKey.getParams().getMlDsaInstance()))
              .setClassicalAlgorithm(
                  CLASSICAL_ALGORITHM_CONVERTER.fromProtoEnum(
                      protoKey.getParams().getClassicalAlgorithm()))
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();

      ProtoKeySerialization mlDsaKeySerialization =
          ProtoKeySerialization.create(
              protoKey.getMlDsaPrivateKey().getTypeUrl(),
              protoKey.getMlDsaPrivateKey().getValue(),
              ProtoConversions.fromProto(protoKey.getMlDsaPrivateKey().getKeyMaterialType()),
              OutputPrefixType.RAW,
              /* idRequirement= */ null);
      Key parsedMlDsaKey = SERIALIZATION_REGISTRY.parseKey(mlDsaKeySerialization, access);
      if (!(parsedMlDsaKey instanceof MlDsaPrivateKey)) {
        throw new GeneralSecurityException("Parsed ML-DSA key is not an MlDsaPrivateKey");
      }

      ProtoKeySerialization classicalKeySerialization =
          ProtoKeySerialization.create(
              protoKey.getClassicalPrivateKey().getTypeUrl(),
              protoKey.getClassicalPrivateKey().getValue(),
              ProtoConversions.fromProto(protoKey.getClassicalPrivateKey().getKeyMaterialType()),
              OutputPrefixType.RAW,
              /* idRequirement= */ null);
      Key parsedClassicalKey = SERIALIZATION_REGISTRY.parseKey(classicalKeySerialization, access);
      if (!(parsedClassicalKey instanceof SignaturePrivateKey)) {
        throw new GeneralSecurityException("Parsed classical key is not a SignaturePrivateKey");
      }

      CompositeMlDsaPrivateKey.Builder builder =
          CompositeMlDsaPrivateKey.builder()
              .setParameters(parameters)
              .setMlDsaPrivateKey((MlDsaPrivateKey) parsedMlDsaKey)
              .setClassicalPrivateKey((SignaturePrivateKey) parsedClassicalKey);
      if (serialization.getIdRequirementOrNull() != null) {
        builder.setIdRequirement(serialization.getIdRequirementOrNull());
      }
      return builder.build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing CompositeMlDsaPrivateKey failed");
    }
  }

  private CompositeMlDsaProtoSerialization() {}
}
