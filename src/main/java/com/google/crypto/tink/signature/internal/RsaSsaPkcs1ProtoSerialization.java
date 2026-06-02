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

package com.google.crypto.tink.signature.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.internal.SerializationRegistry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link RsaSsaPkcs1PrivateKey} and {@link RsaSsaPkcs1PublicKey}
 * objects and {@link RsaSsaPkcs1Parameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class RsaSsaPkcs1ProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  private static final Bytes PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL);
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";
  private static final Bytes PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL);

  private static final ParametersSerializer<RsaSsaPkcs1Parameters, ProtoParametersSerialization>
      PARAMETERS_SERIALIZER =
          ParametersSerializer.create(
              RsaSsaPkcs1ProtoSerialization::serializeParameters, RsaSsaPkcs1Parameters.class);

  private static final ParametersParser<ProtoParametersSerialization> PARAMETERS_PARSER =
      ParametersParser.create(
          RsaSsaPkcs1ProtoSerialization::parseParameters, PRIVATE_TYPE_URL_BYTES);

  private static final KeySerializer<RsaSsaPkcs1PublicKey> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(
          RsaSsaPkcs1ProtoSerialization::serializePublicKey, RsaSsaPkcs1PublicKey.class);

  private static final KeyParser PUBLIC_KEY_PARSER =
      KeyParser.create(RsaSsaPkcs1ProtoSerialization::parsePublicKey, PUBLIC_TYPE_URL_BYTES);

  private static final KeySerializer<RsaSsaPkcs1PrivateKey> PRIVATE_KEY_SERIALIZER =
      KeySerializer.create(
          RsaSsaPkcs1ProtoSerialization::serializePrivateKey, RsaSsaPkcs1PrivateKey.class);

  private static final KeyParser PRIVATE_KEY_PARSER =
      KeyParser.create(RsaSsaPkcs1ProtoSerialization::parsePrivateKey, PRIVATE_TYPE_URL_BYTES);

  private static com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType toOutputPrefixType(
      RsaSsaPkcs1Parameters.Variant variant) throws GeneralSecurityException {
    if (variant.equals(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW;
    }
    if (variant.equals(RsaSsaPkcs1Parameters.Variant.TINK)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK;
    }
    if (variant.equals(RsaSsaPkcs1Parameters.Variant.CRUNCHY)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY;
    }
    if (variant.equals(RsaSsaPkcs1Parameters.Variant.LEGACY)) {
      return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  private static RsaSsaPkcs1Parameters.Variant toVariant(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW) {
      return RsaSsaPkcs1Parameters.Variant.NO_PREFIX;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK) {
      return RsaSsaPkcs1Parameters.Variant.TINK;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY) {
      return RsaSsaPkcs1Parameters.Variant.CRUNCHY;
    }
    if (outputPrefixType == com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY) {
      return RsaSsaPkcs1Parameters.Variant.LEGACY;
    }
    throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType);
  }

  private static final EnumTypeProtoConverter<HashType, RsaSsaPkcs1Parameters.HashType>
      HASH_TYPE_CONVERTER =
          EnumTypeProtoConverter.<HashType, RsaSsaPkcs1Parameters.HashType>builder()
              .add(HashType.SHA256, RsaSsaPkcs1Parameters.HashType.SHA256)
              .add(HashType.SHA384, RsaSsaPkcs1Parameters.HashType.SHA384)
              .add(HashType.SHA512, RsaSsaPkcs1Parameters.HashType.SHA512)
              .build();

  private static com.google.crypto.tink.proto.RsaSsaPkcs1Params getProtoParams(
      RsaSsaPkcs1Parameters parameters) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.RsaSsaPkcs1Params.newBuilder()
        .setHashType(HASH_TYPE_CONVERTER.toProtoEnum(parameters.getHashType()))
        .build();
  }

  /** Encodes a BigInteger using a big-endian encoding. */
  private static ByteString encodeBigInteger(BigInteger i) {
    // Note that toBigEndianBytes() returns the minimal big-endian encoding using the two's
    // complement representation. This means that the encoding may have a leading zero.
    byte[] encoded = BigIntegerEncoding.toBigEndianBytes(i);
    return ByteString.copyFrom(encoded);
  }

  private static com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey getProtoPublicKey(
      RsaSsaPkcs1PublicKey key) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
        .setParams(getProtoParams(key.getParameters()))
        .setN(encodeBigInteger(key.getModulus()))
        .setE(encodeBigInteger(key.getParameters().getPublicExponent()))
        .build();
  }

  private static ProtoParametersSerialization serializeParameters(RsaSsaPkcs1Parameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL,
        toOutputPrefixType(parameters.getVariant()),
        com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.newBuilder()
            .setParams(getProtoParams(parameters))
            .setModulusSizeInBits(parameters.getModulusSizeBits())
            .setPublicExponent(encodeBigInteger(parameters.getPublicExponent()))
            .build()
            .toByteString());
  }

  private static ProtoKeySerialization serializePublicKey(
      RsaSsaPkcs1PublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        getProtoPublicKey(key).toByteString(),
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static ByteString encodeSecretBigInteger(SecretBigInteger i, SecretKeyAccess access) {
    return encodeBigInteger(i.getBigInteger(access));
  }

  private static ProtoKeySerialization serializePrivateKey(
      RsaSsaPkcs1PrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    SecretKeyAccess a = SecretKeyAccess.requireAccess(access);
    com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey protoPrivateKey =
        com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(getProtoPublicKey(key.getPublicKey()))
            .setD(encodeSecretBigInteger(key.getPrivateExponent(), a))
            .setP(encodeSecretBigInteger(key.getPrimeP(), a))
            .setQ(encodeSecretBigInteger(key.getPrimeQ(), a))
            .setDp(encodeSecretBigInteger(key.getPrimeExponentP(), a))
            .setDq(encodeSecretBigInteger(key.getPrimeExponentQ(), a))
            .setCrt(encodeSecretBigInteger(key.getCrtCoefficient(), a))
            .build();
    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        protoPrivateKey.toByteString(),
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  private static BigInteger decodeBigInteger(ByteString data) {
    return BigIntegerEncoding.fromUnsignedBigEndianBytes(data.toByteArray());
  }

  private static RsaSsaPkcs1Parameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPkcs1ProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat format;
    try {
      format =
          com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPkcs1Parameters failed: ", e);
    }
    return RsaSsaPkcs1Parameters.builder()
        .setHashType(HASH_TYPE_CONVERTER.fromProtoEnum(format.getParams().getHashType()))
        .setPublicExponent(decodeBigInteger(format.getPublicExponent()))
        .setModulusSizeBits(format.getModulusSizeInBits())
        .setVariant(
            toVariant(serialization.getOutputPrefixType()))
        .build();
  }

  @SuppressWarnings("UnusedException")
  private static RsaSsaPkcs1PublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPkcs1ProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey protoKey =
          com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      BigInteger modulus = decodeBigInteger(protoKey.getN());
      int modulusSizeInBits = modulus.bitLength();
      RsaSsaPkcs1Parameters parameters =
          RsaSsaPkcs1Parameters.builder()
              .setHashType(HASH_TYPE_CONVERTER.fromProtoEnum(protoKey.getParams().getHashType()))
              .setPublicExponent(decodeBigInteger(protoKey.getE()))
              .setModulusSizeBits(modulusSizeInBits)
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      return RsaSsaPkcs1PublicKey.builder()
          .setParameters(parameters)
          .setModulus(modulus)
          .setIdRequirement(serialization.getIdRequirementOrNull())
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPkcs1PublicKey failed");
    }
  }

  private static SecretBigInteger decodeSecretBigInteger(ByteString data, SecretKeyAccess access) {
    return SecretBigInteger.fromBigInteger(
        BigIntegerEncoding.fromUnsignedBigEndianBytes(data.toByteArray()), access);
  }

  @SuppressWarnings("UnusedException")
  private static RsaSsaPkcs1PrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to RsaSsaPkcs1ProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey protoKey =
          com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }
      com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey protoPublicKey = protoKey.getPublicKey();
      if (protoPublicKey.getVersion() != 0) {
        throw new GeneralSecurityException("Only version 0 keys are accepted");
      }

      BigInteger modulus = decodeBigInteger(protoPublicKey.getN());
      int modulusSizeInBits = modulus.bitLength();
      BigInteger publicExponent = decodeBigInteger(protoPublicKey.getE());
      RsaSsaPkcs1Parameters parameters =
          RsaSsaPkcs1Parameters.builder()
              .setHashType(
                  HASH_TYPE_CONVERTER.fromProtoEnum(protoPublicKey.getParams().getHashType()))
              .setPublicExponent(publicExponent)
              .setModulusSizeBits(modulusSizeInBits)
              .setVariant(toVariant(serialization.getOutputPrefixType()))
              .build();
      RsaSsaPkcs1PublicKey publicKey =
          RsaSsaPkcs1PublicKey.builder()
              .setParameters(parameters)
              .setModulus(modulus)
              .setIdRequirement(serialization.getIdRequirementOrNull())
              .build();

      SecretKeyAccess a = SecretKeyAccess.requireAccess(access);
      return RsaSsaPkcs1PrivateKey.builder()
          .setPublicKey(publicKey)
          .setPrimes(
              decodeSecretBigInteger(protoKey.getP(), a),
              decodeSecretBigInteger(protoKey.getQ(), a))
          .setPrivateExponent(decodeSecretBigInteger(protoKey.getD(), a))
          .setPrimeExponents(
              decodeSecretBigInteger(protoKey.getDp(), a),
              decodeSecretBigInteger(protoKey.getDq(), a))
          .setCrtCoefficient(decodeSecretBigInteger(protoKey.getCrt(), a))
          .build();
    } catch (InvalidProtocolBufferException | IllegalArgumentException e) {
      throw new GeneralSecurityException("Parsing RsaSsaPkcs1PrivateKey failed");
    }
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

  public static void register(SerializationRegistry.Builder registryBuilder)
      throws GeneralSecurityException {
    registryBuilder.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registryBuilder.registerParametersParser(PARAMETERS_PARSER);
    registryBuilder.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registryBuilder.registerKeyParser(PUBLIC_KEY_PARSER);
    registryBuilder.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registryBuilder.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private RsaSsaPkcs1ProtoSerialization() {}
}
