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

package com.google.crypto.tink.jwt.internal;

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
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.proto.JwtMlDsaAlgorithm;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link JwtMlDsaPrivateKey}, {@link JwtMlDsaPublicKey}, and {@link
 * JwtMlDsaParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class JwtMlDsaProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey";

  private static final ParametersSerializer<JwtMlDsaParameters> PARAMETERS_SERIALIZER =
      ParametersSerializer.create(
          JwtMlDsaProtoSerialization::serializeParameters, JwtMlDsaParameters.class);
  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(JwtMlDsaProtoSerialization::parseParameters, TYPE_URL);
  private static final KeySerializer<JwtMlDsaPublicKey> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(JwtMlDsaProtoSerialization::serializePublicKey, JwtMlDsaPublicKey.class);
  private static final KeyParser PUBLIC_KEY_PARSER =
      KeyParser.create(JwtMlDsaProtoSerialization::parsePublicKey, PUBLIC_TYPE_URL);
  private static final KeySerializer<JwtMlDsaPrivateKey> PRIVATE_KEY_SERIALIZER =
      KeySerializer.create(
          JwtMlDsaProtoSerialization::serializePrivateKey, JwtMlDsaPrivateKey.class);
  private static final KeyParser PRIVATE_KEY_PARSER =
      KeyParser.create(JwtMlDsaProtoSerialization::parsePrivateKey, TYPE_URL);

  private static JwtMlDsaAlgorithm toProtoAlgorithm(JwtMlDsaParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return JwtMlDsaAlgorithm.ML_DSA44;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return JwtMlDsaAlgorithm.ML_DSA65;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return JwtMlDsaAlgorithm.ML_DSA87;
    }
    throw new GeneralSecurityException("Unable to serialize algorithm: " + algorithm);
  }

  private static JwtMlDsaParameters.Algorithm toAlgorithm(JwtMlDsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ML_DSA44:
        return JwtMlDsaParameters.Algorithm.ML_DSA_44;
      case ML_DSA65:
        return JwtMlDsaParameters.Algorithm.ML_DSA_65;
      case ML_DSA87:
        return JwtMlDsaParameters.Algorithm.ML_DSA_87;
      default:
        throw new GeneralSecurityException("Unable to parse algorithm: " + algorithm.getNumber());
    }
  }

  private static com.google.crypto.tink.proto.JwtMlDsaKeyFormat serializeToJwtMlDsaKeyFormat(
      JwtMlDsaParameters parameters) throws GeneralSecurityException {
    if (!parameters.getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.IGNORED)
        && !parameters
            .getKidStrategy()
            .equals(JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
      throw new GeneralSecurityException(
          "Unable to serialize Parameters object with KidStrategy " + parameters.getKidStrategy());
    }
    return com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
        .setVersion(0)
        .setAlgorithm(toProtoAlgorithm(parameters.getAlgorithm()))
        .build();
  }

  public static ProtoParametersSerialization serializeParameters(JwtMlDsaParameters parameters)
      throws GeneralSecurityException {
    OutputPrefixType outputPrefixType = OutputPrefixType.TINK;
    if (parameters.getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.IGNORED)) {
      outputPrefixType = OutputPrefixType.RAW;
    }
    return ProtoParametersSerialization.create(
        TYPE_URL, outputPrefixType, serializeToJwtMlDsaKeyFormat(parameters).toByteString());
  }

  public static JwtMlDsaParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to JwtMlDsaParameters.parseParameters: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.JwtMlDsaKeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.JwtMlDsaKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing JwtMlDsaKeyFormat failed: ", e);
    }
    if (format.getVersion() != 0) {
      throw new GeneralSecurityException(
          "Parsing JwtMlDsaParameters failed: unknown version " + format.getVersion());
    }
    JwtMlDsaParameters.KidStrategy kidStrategy = null;
    if (serialization.getOutputPrefixType().equals(OutputPrefixType.TINK)) {
      kidStrategy = JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID;
    }
    if (serialization.getOutputPrefixType().equals(OutputPrefixType.RAW)) {
      kidStrategy = JwtMlDsaParameters.KidStrategy.IGNORED;
    }
    if (kidStrategy == null) {
      throw new GeneralSecurityException("Invalid OutputPrefixType for JwtMlDsaKeyFormat");
    }
    return JwtMlDsaParameters.create(kidStrategy, toAlgorithm(format.getAlgorithm()));
  }

  private static OutputPrefixType toProtoOutputPrefixType(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK) {
      return OutputPrefixType.TINK;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY) {
      return OutputPrefixType.LEGACY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW) {
      return OutputPrefixType.RAW;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY) {
      return OutputPrefixType.CRUNCHY;
    }
    throw new GeneralSecurityException("Unknown OutputPrefixType: " + outputPrefixType);
  }

  private static OutputPrefixType toProtoOutputPrefixType(JwtMlDsaParameters parameters) {
    if (parameters.getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
      return OutputPrefixType.TINK;
    }
    return OutputPrefixType.RAW;
  }

  private static com.google.crypto.tink.proto.JwtMlDsaPublicKey serializePublicKey(
      JwtMlDsaPublicKey key) throws GeneralSecurityException {
    com.google.crypto.tink.proto.JwtMlDsaPublicKey.Builder builder =
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(toProtoAlgorithm(key.getParameters().getAlgorithm()))
            .setKeyValue(
                ByteString.copyFrom(
                    key.getMlDsaPublicKey().getSerializedPublicKey().toByteArray()));
    if (key.getParameters().getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.CUSTOM)) {
      builder.setCustomKid(
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
              .setValue(key.getKid().get())
              .build());
    }
    return builder.build();
  }

  public static ProtoKeySerialization serializePublicKey(
      JwtMlDsaPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        serializePublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        toProtoOutputPrefixType(key.getParameters()),
        key.getIdRequirementOrNull());
  }

  private static JwtMlDsaPublicKey parsePublicKeyFromProto(
      com.google.crypto.tink.proto.JwtMlDsaPublicKey protoKey,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (protoKey.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted");
    }

    JwtMlDsaParameters parameters = null;
    JwtMlDsaPublicKey.Builder keyBuilder = JwtMlDsaPublicKey.builder();

    if (outputPrefixType.equals(OutputPrefixType.TINK)) {
      if (protoKey.hasCustomKid()) {
        throw new GeneralSecurityException(
            "Keys serialized with OutputPrefixType TINK should not have a custom kid");
      }
      if (idRequirement == null) {
        throw new GeneralSecurityException(
            "Keys serialized with OutputPrefixType TINK need an ID Requirement");
      }
      parameters =
          JwtMlDsaParameters.create(
              JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
              toAlgorithm(protoKey.getAlgorithm()));
      keyBuilder.setIdRequirement(idRequirement);
    } else if (outputPrefixType.equals(OutputPrefixType.RAW)) {
      if (protoKey.hasCustomKid()) {
        parameters =
            JwtMlDsaParameters.create(
                JwtMlDsaParameters.KidStrategy.CUSTOM, toAlgorithm(protoKey.getAlgorithm()));
        keyBuilder.setCustomKid(protoKey.getCustomKid().getValue());
      } else {
        parameters =
            JwtMlDsaParameters.create(
                JwtMlDsaParameters.KidStrategy.IGNORED, toAlgorithm(protoKey.getAlgorithm()));
      }
    } else {
      throw new GeneralSecurityException("Unsupported output prefix: " + outputPrefixType);
    }
    keyBuilder.setPublicKeyBytes(Bytes.copyFrom(protoKey.getKeyValue().toByteArray()));
    return keyBuilder.setParameters(parameters).build();
  }

  @SuppressWarnings("UnusedException")
  public static JwtMlDsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to JwtMlDsaProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.JwtMlDsaPublicKey protoKey;
    try {
      protoKey =
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing JwtMlDsaPublicKey failed: ", e);
    }
    return parsePublicKeyFromProto(
        protoKey,
        toProtoOutputPrefixType(serialization.getOutputPrefixType()),
        serialization.getIdRequirementOrNull());
  }

  private static com.google.crypto.tink.proto.JwtMlDsaPrivateKey serializePrivateKeyToProto(
      JwtMlDsaPrivateKey key, SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
        .setPublicKey(serializePublicKey(key.getPublicKey()))
        .setKeyValue(ByteString.copyFrom(key.getPrivateSeed().toByteArray(access)))
        .build();
  }

  public static ProtoKeySerialization serializePrivateKey(
      JwtMlDsaPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        serializePrivateKeyToProto(key, SecretKeyAccess.requireAccess(access)).toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        toProtoOutputPrefixType(key.getParameters()),
        key.getIdRequirementOrNull());
  }

  @SuppressWarnings("UnusedException")
  public static JwtMlDsaPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to JwtMlDsaProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.JwtMlDsaPrivateKey protoKey;
    try {
      protoKey =
          com.google.crypto.tink.proto.JwtMlDsaPrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing JwtMlDsaPrivateKey failed: ", e);
    }
    if (protoKey.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted");
    }
    JwtMlDsaPublicKey publicKey =
        parsePublicKeyFromProto(
            protoKey.getPublicKey(),
            toProtoOutputPrefixType(serialization.getOutputPrefixType()),
            serialization.getIdRequirementOrNull());
    return JwtMlDsaPrivateKey.create(
        publicKey, SecretBytes.copyFrom(protoKey.getKeyValue().toByteArray(), access));
  }

  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registry.registerKeyParser(PUBLIC_KEY_PARSER);
    registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registry.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private JwtMlDsaProtoSerialization() {}
}
