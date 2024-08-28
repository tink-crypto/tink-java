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

package com.google.crypto.tink.aead.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.XAesGcmKey;
import com.google.crypto.tink.aead.XAesGcmParameters;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link XAesGcmKey} objects and {@link XAesGcmParameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class XAesGcmProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.XAesGcmKey";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);
  private static final int KEY_SIZE_BYTES = 32;

  private static final ParametersSerializer<XAesGcmParameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              XAesGcmProtoSerialization::serializeParameters,
              XAesGcmParameters.class,
              ProtoParametersSerialization.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          XAesGcmProtoSerialization::parseParameters,
          TYPE_URL_BYTES,
          ProtoParametersSerialization.class);

  private static final KeySerializer<XAesGcmKey, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          XAesGcmProtoSerialization::serializeKey, XAesGcmKey.class, ProtoKeySerialization.class);

  private static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          XAesGcmProtoSerialization::parseKey, TYPE_URL_BYTES, ProtoKeySerialization.class);

  private static OutputPrefixType toProtoOutputPrefixType(XAesGcmParameters.Variant variant)
      throws GeneralSecurityException {
    if (Objects.equals(variant, XAesGcmParameters.Variant.TINK)) {
      return OutputPrefixType.TINK;
    }
    if (Objects.equals(variant, XAesGcmParameters.Variant.CRUNCHY)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (Objects.equals(variant, XAesGcmParameters.Variant.NO_PREFIX)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static XAesGcmParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return XAesGcmParameters.Variant.TINK;
      /* Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key */
      case CRUNCHY:
      case LEGACY:
        return XAesGcmParameters.Variant.CRUNCHY;
      case RAW:
        return XAesGcmParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType.getNumber());
    }
  }

  private static ProtoParametersSerialization serializeParameters(XAesGcmParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(
                com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                    .setParams(
                        com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                            .setSaltSize(parameters.getSaltSizeBytes())
                            .build())
                    .build()
                    .toByteString())
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
            .build());
  }

  private static ProtoKeySerialization serializeKey(
      XAesGcmKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .setParams(
                com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                    .setSaltSize(key.getParameters().getSaltSizeBytes())
                    .build())
            .build()
            .toByteString(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static XAesGcmParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to XAesGcmProtoSerialization.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    com.google.crypto.tink.proto.XAesGcmKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.XAesGcmKeyFormat.parseFrom(
              serialization.getKeyTemplate().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing XAesGcmParameters failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 parameters are accepted");
    }
    return XAesGcmParameters.create(
        toVariant(serialization.getKeyTemplate().getOutputPrefixType()),
        format.getParams().getSaltSize());
  }

  @SuppressWarnings("UnusedException")
  private static XAesGcmKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to XAesGcmProtoSerialization.parseKey");
    }
    try {
      com.google.crypto.tink.proto.XAesGcmKey protoKey =
          com.google.crypto.tink.proto.XAesGcmKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }

      if (protoKey.getKeyValue().size() != KEY_SIZE_BYTES) {
        throw new GeneralSecurityException("Only 32 byte key size is accepted");
      }
      return XAesGcmKey.create(
          XAesGcmParameters.create(
              toVariant(serialization.getOutputPrefixType()), protoKey.getParams().getSaltSize()),
          SecretBytes.copyFrom(
              protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing XAesGcmKey failed");
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

  private XAesGcmProtoSerialization() {}
}
