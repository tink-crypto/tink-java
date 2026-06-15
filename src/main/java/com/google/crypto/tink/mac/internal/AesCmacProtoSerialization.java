// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link AesCmacKey} objects and {@link AesCmacParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCmacProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCmacKey";

  private static final ParametersSerializer<AesCmacParameters>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesCmacProtoSerialization::serializeParameters, AesCmacParameters.class);

  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(AesCmacProtoSerialization::parseParameters, TYPE_URL);

  private static final KeySerializer<AesCmacKey> KEY_SERIALIZER =
      KeySerializer.create(AesCmacProtoSerialization::serializeKey, AesCmacKey.class);

  private static final KeyParser KEY_PARSER =
      KeyParser.create(AesCmacProtoSerialization::parseKey, TYPE_URL);

  private static OutputPrefixType toOutputPrefixType(AesCmacParameters.Variant variant)
      throws GeneralSecurityException {
    if (variant.equals(AesCmacParameters.Variant.TINK)) {
      return OutputPrefixType.TINK;
    }
    if (variant.equals(AesCmacParameters.Variant.CRUNCHY)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (variant.equals(AesCmacParameters.Variant.NO_PREFIX)) {
      return OutputPrefixType.RAW;
    }
    if (variant.equals(AesCmacParameters.Variant.LEGACY)) {
      return OutputPrefixType.LEGACY;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesCmacParameters.Variant toVariant(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK) {
      return AesCmacParameters.Variant.TINK;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY) {
      return AesCmacParameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY) {
      return AesCmacParameters.Variant.LEGACY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW) {
      return AesCmacParameters.Variant.NO_PREFIX;
    }
    throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
  }


  private static com.google.crypto.tink.proto.AesCmacParams getProtoParams(
      AesCmacParameters parameters) {
    return com.google.crypto.tink.proto.AesCmacParams.newBuilder()
        .setTagSize(parameters.getCryptographicTagSizeBytes())
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(AesCmacParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        TYPE_URL,
        toOutputPrefixType(parameters.getVariant()),
        com.google.crypto.tink.proto.AesCmacKeyFormat.newBuilder()
            .setParams(getProtoParams(parameters))
            .setKeySize(parameters.getKeySizeBytes())
            .build()
            .toByteString());
  }

  private static ProtoKeySerialization serializeKey(
      AesCmacKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesCmacKey.newBuilder()
            .setParams(getProtoParams(key.getParameters()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getAesKey().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesCmacParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.AesCmacKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesCmacKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesCmacParameters failed: ", e);
    }

    return AesCmacParameters.builder()
        .setKeySizeBytes(format.getKeySize())
        .setTagSizeBytes(format.getParams().getTagSize())
        .setVariant(toVariant(serialization.getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static AesCmacKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesCmacProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesCmacKey protoKey =
          com.google.crypto.tink.proto.AesCmacKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesCmacParameters parameters =
          AesCmacParameters.builder()
              .setKeySizeBytes(protoKey.getKeyValue().size())
              .setTagSizeBytes(protoKey.getParams().getTagSize())
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return AesCmacKey.builder()
          .setParameters(parameters)
          .setAesKeyBytes(SecretBytes.copyFrom(
                protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing AesCmacKey failed");
    }
  }

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(KEY_SERIALIZER);
    registry.registerKeyParser(KEY_PARSER);
  }

  public static void register(SerializationRegistry.Builder registryBuilder)
      throws GeneralSecurityException {
    registryBuilder.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registryBuilder.registerParametersParser(PARAMETERS_PARSER);
    registryBuilder.registerKeySerializer(KEY_SERIALIZER);
    registryBuilder.registerKeyParser(KEY_PARSER);
  }

  private AesCmacProtoSerialization() {}
}
