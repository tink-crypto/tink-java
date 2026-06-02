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
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Methods to serialize and parse {@link AesGcmKey} objects and {@link AesGcmParameters} objects */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesGcmProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  private static final ParametersSerializer<AesGcmParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              AesGcmProtoSerialization::serializeParameters, AesGcmParameters.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(AesGcmProtoSerialization::parseParameters, TYPE_URL_BYTES);

  private static final KeySerializer<AesGcmKey> KEY_SERIALIZER =
      KeySerializer.create(AesGcmProtoSerialization::serializeKey, AesGcmKey.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(AesGcmProtoSerialization::parseKey, TYPE_URL_BYTES);

  private static OutputPrefixType toProtoOutputPrefixType(AesGcmParameters.Variant variant)
      throws GeneralSecurityException {
    if (variant.equals(AesGcmParameters.Variant.TINK)) {
      return OutputPrefixType.TINK;
    }
    if (variant.equals(AesGcmParameters.Variant.CRUNCHY)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (variant.equals(AesGcmParameters.Variant.NO_PREFIX)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static AesGcmParameters.Variant toVariant(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK) {
      return AesGcmParameters.Variant.TINK;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY) {
      return AesGcmParameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY) {
      return AesGcmParameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW) {
      return AesGcmParameters.Variant.NO_PREFIX;
    }
    throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
  }


  private static void validateParameters(AesGcmParameters parameters)
      throws GeneralSecurityException {
    /* Current implementation restricts tag size to 16 bytes */
    if (parameters.getTagSizeBytes() != 16) {
      throw new GeneralSecurityException(
          String.format(
              "Invalid tag size in bytes %d. Currently Tink only supports serialization of AES GCM"
                  + " keys with tag size equal to 16 bytes.",
              parameters.getTagSizeBytes()));
    }
    /* Current implementation restricts IV size to 12 bytes */
    if (parameters.getIvSizeBytes() != 12) {
      throw new GeneralSecurityException(
          String.format(
              "Invalid IV size in bytes %d. Currently Tink only supports serialization of AES GCM"
                  + " keys with IV size equal to 12 bytes.",
              parameters.getIvSizeBytes()));
    }
  }

  private static ProtoParametersSerialization serializeParameters(AesGcmParameters parameters)
      throws GeneralSecurityException {
    validateParameters(parameters);
    return ProtoParametersSerialization.create(
        TYPE_URL,
        toProtoOutputPrefixType(parameters.getVariant()),
        com.google.crypto.tink.proto.AesGcmKeyFormat.newBuilder()
            .setKeySize(parameters.getKeySizeBytes())
            .build()
            .toByteString());
  }

  private static ProtoKeySerialization serializeKey(AesGcmKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    validateParameters(key.getParameters());
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.AesGcmKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static AesGcmParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.AesGcmKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.AesGcmKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 parameters are accepted");
    }
    return AesGcmParameters.builder()
        .setKeySizeBytes(format.getKeySize())
        /*
         * Currently, the Tink subtle implementation has the following restrictions: IV is a
         * uniformly random initialization vector of length 12 and the tag is restricted to 16
         * bytes.
         */
        .setIvSizeBytes(12)
        .setTagSizeBytes(16)
        .setVariant(toVariant(serialization.getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static AesGcmKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to AesGcmProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.AesGcmKey protoKey =
          com.google.crypto.tink.proto.AesGcmKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      AesGcmParameters parameters =
          AesGcmParameters.builder()
              .setKeySizeBytes(protoKey.getKeyValue().size())
              .setIvSizeBytes(12)
              .setTagSizeBytes(16)
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return AesGcmKey.builder()
          .setParameters(parameters)
          .setKeyBytes(
              SecretBytes.copyFrom(
                  protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)))
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing AesGcmKey failed");
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

  private AesGcmProtoSerialization() {}
}
