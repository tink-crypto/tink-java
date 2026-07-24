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

package com.google.crypto.tink.hybrid.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.HpkeUtil;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.RestrictedApi;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link HpkePrivateKey}, {@link HpkePublicKey}, and {@link
 * HpkeParameters} objects.
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HpkeProtoSerialization {
  private static final int VERSION = 0;
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";

  private static OutputPrefixType toOutputPrefixType(HpkeParameters.Variant variant)
      throws GeneralSecurityException {
    if (variant.equals(HpkeParameters.Variant.NO_PREFIX)) {
      return OutputPrefixType.RAW;
    }
    if (variant.equals(HpkeParameters.Variant.TINK)) {
      return OutputPrefixType.TINK;
    }
    if (variant.equals(HpkeParameters.Variant.CRUNCHY)) {
      return OutputPrefixType.CRUNCHY;
    }
    throw new GeneralSecurityException("unknown variant: " + variant);
  }

  private static HpkeParameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    if (outputPrefixType.equals(OutputPrefixType.RAW)) {
      return HpkeParameters.Variant.NO_PREFIX;
    }
    if (outputPrefixType.equals(OutputPrefixType.TINK)) {
      return HpkeParameters.Variant.TINK;
    }
    if (outputPrefixType.equals(OutputPrefixType.CRUNCHY)
        || outputPrefixType.equals(OutputPrefixType.LEGACY)) {
      return HpkeParameters.Variant.CRUNCHY;
    }
    throw new GeneralSecurityException("unknown variant: " + outputPrefixType);
  }

  private static final EnumTypeProtoConverter<HpkeKem, HpkeParameters.KemId> KEM_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeKem, HpkeParameters.KemId>builder()
          .add(HpkeKem.DHKEM_P256_HKDF_SHA256, HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
          .add(HpkeKem.DHKEM_P384_HKDF_SHA384, HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
          .add(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
          .add(HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
          .add(HpkeKem.X_WING, HpkeParameters.KemId.X_WING)
          .build();

  private static final EnumTypeProtoConverter<HpkeKdf, HpkeParameters.KdfId> KDF_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeKdf, HpkeParameters.KdfId>builder()
          .add(HpkeKdf.HKDF_SHA256, HpkeParameters.KdfId.HKDF_SHA256)
          .add(HpkeKdf.HKDF_SHA384, HpkeParameters.KdfId.HKDF_SHA384)
          .add(HpkeKdf.HKDF_SHA512, HpkeParameters.KdfId.HKDF_SHA512)
          .build();

  private static final EnumTypeProtoConverter<HpkeAead, HpkeParameters.AeadId> AEAD_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HpkeAead, HpkeParameters.AeadId>builder()
          .add(HpkeAead.AES_128_GCM, HpkeParameters.AeadId.AES_128_GCM)
          .add(HpkeAead.AES_256_GCM, HpkeParameters.AeadId.AES_256_GCM)
          .add(HpkeAead.CHACHA20_POLY1305, HpkeParameters.AeadId.CHACHA20_POLY1305)
          .build();

  private static com.google.crypto.tink.proto.HpkeParams toProtoParameters(HpkeParameters params)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HpkeParams.newBuilder()
        .setKem(KEM_TYPE_CONVERTER.toProtoEnum(params.getKemId()))
        .setKdf(KDF_TYPE_CONVERTER.toProtoEnum(params.getKdfId()))
        .setAead(AEAD_TYPE_CONVERTER.toProtoEnum(params.getAeadId()))
        .build();
  }

  private static com.google.crypto.tink.proto.HpkePublicKey toProtoPublicKey(HpkePublicKey key)
      throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
        .setVersion(VERSION)
        .setParams(toProtoParameters(key.getParameters()))
        .setPublicKey(ByteString.copyFrom(key.getPublicKeyBytes().toByteArray()))
        .build();
  }

  private static com.google.crypto.tink.proto.HpkePrivateKey toProtoPrivateKey(
      HpkePrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.proto.HpkePrivateKey.newBuilder()
        .setVersion(VERSION)
        .setPublicKey(toProtoPublicKey(key.getPublicKey()))
        .setPrivateKey(
            ByteString.copyFrom(
                key.getPrivateKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
        .build();
  }

  private static HpkeParameters fromProtoParameters(
      OutputPrefixType outputPrefixType, HpkeParams protoParams) throws GeneralSecurityException {
    return HpkeParameters.builder()
        .setVariant(toVariant(outputPrefixType))
        .setKemId(KEM_TYPE_CONVERTER.fromProtoEnum(protoParams.getKem()))
        .setKdfId(KDF_TYPE_CONVERTER.fromProtoEnum(protoParams.getKdf()))
        .setAeadId(AEAD_TYPE_CONVERTER.fromProtoEnum(protoParams.getAead()))
        .build();
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoParametersSerialization serializeParameters(HpkeParameters parameters)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL,
        toOutputPrefixType(parameters.getVariant()),
        HpkeKeyFormat.newBuilder().setParams(toProtoParameters(parameters)).build().toByteString());
  }

  /**
   * Returns the proto serialization of a {@link HpkePublicKey}.
   *
   * @param access may be null for public key material
   * @throws GeneralSecurityException if the key cannot be serialized (e.g. unknown variant)
   */
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePublicKey(
      HpkePublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        toProtoPublicKey(key).toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePrivateKey(
      HpkePrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        toProtoPrivateKey(key, access).toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        toOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static HpkeParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HpkeProtoSerialization.parseParameters: "
              + serialization.getTypeUrl());
    }
    HpkeKeyFormat format;
    try {
      format =
          HpkeKeyFormat.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HpkeParameters failed: ", e);
    }
    return fromProtoParameters(serialization.getOutputPrefixType(), format.getParams());
  }

  private static Bytes encodePublicKeyBytes(HpkeParameters.KemId kemId, byte[] publicKeyBytes)
      throws GeneralSecurityException {
    BigInteger n = BigIntegerEncoding.fromUnsignedBigEndianBytes(publicKeyBytes);
    byte[] encodedPublicKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            n, HpkeUtil.getEncodedPublicKeyLength(kemId));
    return Bytes.copyFrom(encodedPublicKeyBytes);
  }

  @SuppressWarnings("UnusedException")
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static HpkePublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PUBLIC_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HpkeProtoSerialization.parsePublicKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.HpkePublicKey protoKey =
          com.google.crypto.tink.proto.HpkePublicKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != VERSION) {
        throw new GeneralSecurityException("Only version " + VERSION + " keys are accepted");
      }

      HpkeParameters params =
          fromProtoParameters(serialization.getOutputPrefixType(), protoKey.getParams());
      return HpkePublicKey.create(
          params,
          encodePublicKeyBytes(params.getKemId(), protoKey.getPublicKey().toByteArray()),
          serialization.getIdRequirementOrNull());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HpkePublicKey failed");
    }
  }

  private static SecretBytes encodePrivateKeyBytes(
      HpkeParameters.KemId kemId, byte[] privateKeyBytes, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    BigInteger n = BigIntegerEncoding.fromUnsignedBigEndianBytes(privateKeyBytes);
    byte[] encodedPrivateKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            n, HpkeUtil.getEncodedPrivateKeyLength(kemId));
    return SecretBytes.copyFrom(encodedPrivateKeyBytes, SecretKeyAccess.requireAccess(access));
  }

  @SuppressWarnings("UnusedException") // Prevents leaking key material
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static HpkePrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(PRIVATE_TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to HpkeProtoSerialization.parsePrivateKey: "
              + serialization.getTypeUrl());
    }
    try {
      com.google.crypto.tink.proto.HpkePrivateKey protoKey =
          com.google.crypto.tink.proto.HpkePrivateKey.parseFrom(
              serialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
      if (protoKey.getVersion() != VERSION) {
        throw new GeneralSecurityException("Only version " + VERSION + " keys are accepted");
      }
      com.google.crypto.tink.proto.HpkePublicKey protoPublicKey = protoKey.getPublicKey();
      if (protoPublicKey.getVersion() != VERSION) {
        throw new GeneralSecurityException("Only version " + VERSION + " keys are accepted");
      }
      HpkeParameters params =
          fromProtoParameters(serialization.getOutputPrefixType(), protoPublicKey.getParams());
      HpkePublicKey publicKey =
          HpkePublicKey.create(
              params,
              encodePublicKeyBytes(params.getKemId(), protoPublicKey.getPublicKey().toByteArray()),
              serialization.getIdRequirementOrNull());
      return HpkePrivateKey.create(
          publicKey,
          encodePrivateKeyBytes(params.getKemId(), protoKey.getPrivateKey().toByteArray(), access));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing HpkePrivateKey failed");
    }
  }

  private HpkeProtoSerialization() {}
}
