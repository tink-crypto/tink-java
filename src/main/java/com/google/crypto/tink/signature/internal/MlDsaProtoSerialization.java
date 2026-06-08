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

package com.google.crypto.tink.signature.internal;


import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.proto.MlDsaKeyFormat;
import com.google.crypto.tink.proto.MlDsaParams;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link MlDsaPrivateKey} and {@link MlDsaPublicKey} objects and
 * {@link MlDsaParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class MlDsaProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

  private static final ParametersSerializer<MlDsaParameters>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              MlDsaProtoSerialization::serializeParameters, MlDsaParameters.class);

  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(MlDsaProtoSerialization::parseParameters, PRIVATE_TYPE_URL);

  private static final KeySerializer<MlDsaPublicKey> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(MlDsaProtoSerialization::serializePublicKey, MlDsaPublicKey.class);

  private static final KeyParser PUBLIC_KEY_PARSER =
      KeyParser.create(MlDsaProtoSerialization::parsePublicKey, PUBLIC_TYPE_URL);

  private static final KeySerializer<MlDsaPrivateKey> PRIVATE_KEY_SERIALIZER =
      KeySerializer.create(MlDsaProtoSerialization::serializePrivateKey, MlDsaPrivateKey.class);

  private static final KeyParser PRIVATE_KEY_PARSER =
      KeyParser.create(MlDsaProtoSerialization::parsePrivateKey, PRIVATE_TYPE_URL);

  private static com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType toOutputPrefixType(
      MlDsaParameters.Variant variant) throws GeneralSecurityException {
    if (variant.equals(MlDsaParameters.Variant.NO_PREFIX)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW;
    }
    if (variant.equals(MlDsaParameters.Variant.TINK)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK;
    }
    throw new GeneralSecurityException("unknown variant: " + variant);
  }

  private static MlDsaParameters.Variant toVariant(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType.equals(
        com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW)) {
      return MlDsaParameters.Variant.NO_PREFIX;
    }
    if (outputPrefixType.equals(
        com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK)) {
      return MlDsaParameters.Variant.TINK;
    }
    throw new GeneralSecurityException("unknown variant: " + outputPrefixType);
  }

  private static final EnumTypeProtoConverter<
          com.google.crypto.tink.proto.MlDsaInstance, MlDsaParameters.MlDsaInstance>
      INSTANCE_CONVERTER =
          EnumTypeProtoConverter
              .<com.google.crypto.tink.proto.MlDsaInstance, MlDsaParameters.MlDsaInstance>builder()
              .add(
                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_44,
                  MlDsaParameters.MlDsaInstance.ML_DSA_44)
              .add(
                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65,
                  MlDsaParameters.MlDsaInstance.ML_DSA_65)
              .add(
                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87,
                  MlDsaParameters.MlDsaInstance.ML_DSA_87)
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

  /** Registers previously defined parser/serializer objects into a given registry builder. */
  public static void register(SerializationRegistry.Builder registryBuilder)
      throws GeneralSecurityException {
    registryBuilder.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registryBuilder.registerParametersParser(PARAMETERS_PARSER);
    registryBuilder.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registryBuilder.registerKeyParser(PUBLIC_KEY_PARSER);
    registryBuilder.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registryBuilder.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private static MlDsaParams getProtoParams(MlDsaParameters parameters)
      throws GeneralSecurityException {
    return MlDsaParams.newBuilder()
        .setMlDsaInstance(INSTANCE_CONVERTER.toProtoEnum(parameters.getMlDsaInstance()))
        .build();
  }

  private static com.google.crypto.tink.proto.MlDsaPublicKey getProtoPublicKey(MlDsaPublicKey key)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
        .setVersion(0)
        .setParams(getProtoParams(key.getParameters()))
        .setKeyValue(ByteString.copyFrom(key.getSerializedPublicKey().toByteArray()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(MlDsaParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL,
        toOutputPrefixType(parameters.getVariant()),
        MlDsaKeyFormat.newBuilder()
            .setParams(getProtoParams(parameters))
            .setVersion(0)
            .build()
            .toByteString());
  }

  /**
   * Returns the proto serialization of a {@link MlDsaPublicKey}.
   *
   * @param access may be null for public key material
   * @throws GeneralSecurityException if the key cannot be serialized (e.g. unknown variant)
   */
  private static ProtoKeySerialization serializePublicKey(
      MlDsaPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        getProtoPublicKey(key).toByteString(),
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ProtoKeySerialization serializePrivateKey(
      MlDsaPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(getProtoPublicKey(key.getPublicKey()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getPrivateSeed().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static MlDsaParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to MlDsaProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    MlDsaKeyFormat format;
    try {
      format =
          MlDsaKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing MlDsaParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted for ML-DSA.");
    }
    return MlDsaParameters.create(
        INSTANCE_CONVERTER.fromProtoEnum(format.getParams().getMlDsaInstance()),
        toVariant(serialization.getOutputPrefixType()));
  }

  @SuppressWarnings("UnusedException")
  private static MlDsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to MlDsaProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    if (!serialization
        .getKeyMaterialType()
        .equals(com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC)) {
      throw new GeneralSecurityException(
          "Wrong KeyMaterialType for MlDsaPublicKey: " + serialization.getKeyMaterialType());
    }
    try {
      com.google.crypto.tink.proto.MlDsaPublicKey protoKey =
          com.google.crypto.tink.proto.MlDsaPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      MlDsaParameters parameters =
          MlDsaParameters.create(
              INSTANCE_CONVERTER.fromProtoEnum(protoKey.getParams().getMlDsaInstance()),
              toVariant(serialization.getOutputPrefixType()));
      MlDsaPublicKey.Builder builder =
          MlDsaPublicKey.builder()
              .setParameters(parameters)
              .setSerializedPublicKey(Bytes.copyFrom(protoKey.getKeyValue().toByteArray()));
      if (serialization.getIdRequirementOrNull() != null) {
        builder.setIdRequirement(serialization.getIdRequirementOrNull());
      }
      return builder.build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing MlDsaPublicKey failed");
    }
  }

  @SuppressWarnings("UnusedException") // Prevents leaking key material
  private static MlDsaPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to MlDsaProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    if (!serialization
        .getKeyMaterialType()
        .equals(com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE)) {
      throw new GeneralSecurityException(
          "Wrong KeyMaterialType for MlDsaPrivateKey: " + serialization.getKeyMaterialType());
    }
    try {
      com.google.crypto.tink.proto.MlDsaPrivateKey protoKey =
          com.google.crypto.tink.proto.MlDsaPrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      com.google.crypto.tink.proto.MlDsaPublicKey protoPublicKey = protoKey.getPublicKey();
      if (protoPublicKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      MlDsaParameters parameters =
          MlDsaParameters.create(
              INSTANCE_CONVERTER.fromProtoEnum(protoPublicKey.getParams().getMlDsaInstance()),
              toVariant(serialization.getOutputPrefixType()));
      MlDsaPublicKey.Builder builder =
          MlDsaPublicKey.builder()
              .setParameters(parameters)
              .setSerializedPublicKey(Bytes.copyFrom(protoPublicKey.getKeyValue().toByteArray()));
      if (serialization.getIdRequirementOrNull() != null) {
        builder.setIdRequirement(serialization.getIdRequirementOrNull());
      }
      MlDsaPublicKey publicKey = builder.build();

      return MlDsaPrivateKey.createWithoutVerification(
          publicKey,
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing MlDsaPrivateKey failed");
    }
  }

  private MlDsaProtoSerialization() {}
}
