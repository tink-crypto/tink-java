// Copyright 2023 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link AesGcmSivKey} objects and {@link AesGcmSivParameters}
 * objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesGcmSivProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesGcmSivKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<AesGcmSivParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesGcmSivProtoSerialization::serializeParameters, AesGcmSivParameters.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(AesGcmSivProtoSerialization::parseParameters, TYPE_URL_BYTES);

  private static final KeySerializer<AesGcmSivKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(AesGcmSivProtoSerialization::serializeKey, AesGcmSivKey.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(AesGcmSivProtoSerialization::parseKey, TYPE_URL_BYTES);

  private static OutputPrefixType toProtoOutputPrefixType(AesGcmSivParameters.Variant variant)
      throws GeneralSecurityException {
    if (variant.equals(AesGcmSivParameters.Variant.TINK)) {
      return OutputPrefixType.TINK;
    }
    if (variant.equals(AesGcmSivParameters.Variant.CRUNCHY)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (variant.equals(AesGcmSivParameters.Variant.NO_PREFIX)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesGcmSivParameters.Variant toVariant(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK) {
      return AesGcmSivParameters.Variant.TINK;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY) {
      return AesGcmSivParameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY) {
      return AesGcmSivParameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW) {
      return AesGcmSivParameters.Variant.NO_PREFIX;
    }
    throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
  }


  private static ProtoParametersSerialization serializeParameters(AesGcmSivParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        TYPE_URL,
        toProtoOutputPrefixType(parameters.getVariant()),
        com.google.crypto.tink.proto.AesGcmSivKeyFormat.newBuilder()
            .setKeySize(parameters.getKeySizeBytes())
            .build()
            .toByteString());
  }

  private static ProtoKeySerialization serializeKey(
      AesGcmSivKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesGcmSivKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesGcmSivParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmSivProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.AesGcmSivKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesGcmSivKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmSivParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 parameters are accepted");
    }
    return AesGcmSivParameters.builder()
        .setKeySizeBytes(format.getKeySize())
        .setVariant(toVariant(serialization.getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static AesGcmSivKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmSivProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesGcmSivKey protoKey =
          com.google.crypto.tink.proto.AesGcmSivKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesGcmSivParameters parameters =
          AesGcmSivParameters.builder()
              .setKeySizeBytes(protoKey.getKeyValue().size())
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return AesGcmSivKey.builder()
          .setParameters(parameters)
          .setKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmSivKey failed");
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

  private AesGcmSivProtoSerialization() {}
}
