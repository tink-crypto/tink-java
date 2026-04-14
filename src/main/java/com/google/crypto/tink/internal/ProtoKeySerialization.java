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

package com.google.crypto.tink.internal;

import static com.google.crypto.tink.internal.Util.checkedToBytesFromPrintableAscii;

import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * * Represents a {@code Key} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoKeySerialization} objects fully describe a {@code Key} object, but tailored for
 * protocol buffer serialization.
 */
@Immutable
public final class ProtoKeySerialization implements Serialization {
  private final String typeUrl;
  private final Bytes objectIdentifier;
  private final ByteString value;
  private final KeyMaterialType keyMaterialType;
  private final OutputPrefixType outputPrefixType;
  @Nullable private final Integer idRequirement;

  private ProtoKeySerialization(
      String typeUrl,
      Bytes objectIdentifier,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement) {
    this.typeUrl = typeUrl;
    this.objectIdentifier = objectIdentifier;
    this.value = value;
    this.keyMaterialType = keyMaterialType;
    this.outputPrefixType = outputPrefixType;
    this.idRequirement = idRequirement;
  }

  public static ProtoKeySerialization create(
      String typeUrl,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (outputPrefixType == OutputPrefixType.RAW) {
      if (idRequirement != null) {
        throw new GeneralSecurityException(
            "Keys with output prefix type raw should not have an id requirement.");
      }
    } else {
      if (idRequirement == null) {
        throw new GeneralSecurityException(
            "Keys with output prefix type different from raw should have an id requirement.");
      }
    }
    Bytes objectIdentifier = checkedToBytesFromPrintableAscii(typeUrl);
    return new ProtoKeySerialization(
        typeUrl, objectIdentifier, value, keyMaterialType, outputPrefixType, idRequirement);
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  public ByteString getValue() {
    return value;
  }

  /**
   * The contents of the field key_material_type in the message
   * com.google.crypto.tink.proto.KeyData.
   */
  public KeyMaterialType getKeyMaterialTypeProto() {
    return keyMaterialType;
  }

  /**
   * The contents of the field output_prefix_type in the message
   * com.google.crypto.tink.proto.Keyset.Key.
   */
  public OutputPrefixType getOutputPrefixTypeProto() {
    return outputPrefixType;
  }

  /**
   * The id requirement of this key. Guaranteed to be null if getOutputPrefixTypeProto == RAW, otherwise
   * non-null, and equal to the ID this key has to have.
   */
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  /**
   * The object identifier.
   *
   * <p>This is the UTF8 encoding of the result of "getTypeUrl".
   */
  @Override
  public Bytes getObjectIdentifier() {
    return objectIdentifier;
  }

  /** The typeUrl. */
  public String getTypeUrl() {
    return typeUrl;
  }

  private static com.google.crypto.tink.proto.KeyData.KeyMaterialType toProtoKeyMaterialType(
      com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType type)
      throws GeneralSecurityException {
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC)) {
      return com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC;
    }
    if (type.equals(
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE)) {
      return com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
    }
    if (type.equals(
        com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC)) {
      return com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
    }
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE)) {
      return com.google.crypto.tink.proto.KeyData.KeyMaterialType.REMOTE;
    }
    throw new GeneralSecurityException("Unknown KeyMaterialType " + type);
  }

  private static com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType
      fromProtoKeyMaterialType(com.google.crypto.tink.proto.KeyData.KeyMaterialType type)
          throws GeneralSecurityException {
    switch (type) {
      case SYMMETRIC:
        return com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC;
      case ASYMMETRIC_PRIVATE:
        return com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE;
      case ASYMMETRIC_PUBLIC:
        return com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC;
      case REMOTE:
        return com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE;
      default:
        throw new GeneralSecurityException("Unknown KeyMaterialType " + type);
    }
  }

  private static com.google.crypto.tink.proto.OutputPrefixType toProtoOutputPrefixType(
      com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType type)
      throws GeneralSecurityException {
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK)) {
      return com.google.crypto.tink.proto.OutputPrefixType.TINK;
    }
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY)) {
      return com.google.crypto.tink.proto.OutputPrefixType.LEGACY;
    }
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW)) {
      return com.google.crypto.tink.proto.OutputPrefixType.RAW;
    }
    if (type.equals(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY)) {
      return com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY;
    }
    throw new GeneralSecurityException("Unknown OutputPrefixType " + type);
  }

  private static com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType
      fromProtoOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType type)
          throws GeneralSecurityException {
    switch (type) {
      case TINK:
        return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK;
      case LEGACY:
        return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY;
      case RAW:
        return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW;
      case CRUNCHY:
        return com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY;
      default:
        throw new GeneralSecurityException("Unknown OutputPrefixType " + type);
    }
  }

  public static ProtoKeySerialization createFromPublic(
      com.google.crypto.tink.ProtoKeySerialization serialization) throws GeneralSecurityException {
    return create(
        serialization.getTypeUrl(),
        serialization.getValue(),
        toProtoKeyMaterialType(serialization.getKeyMaterialType()),
        toProtoOutputPrefixType(serialization.getOutputPrefixType()),
        serialization.getIdRequirementOrNull());
  }

  public com.google.crypto.tink.ProtoKeySerialization toPublic() throws GeneralSecurityException {
    return com.google.crypto.tink.ProtoKeySerialization.create(
        getTypeUrl(),
        getValue(),
        fromProtoKeyMaterialType(getKeyMaterialTypeProto()),
        fromProtoOutputPrefixType(getOutputPrefixTypeProto()),
        getIdRequirementOrNull());
  }
}
