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

package com.google.crypto.tink;

import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * A representation of a {@link Key} object, prepared for the Tink proto keyset format.
 *
 * <p>{@link ProtoKeySerialization} objects fully describe a {@link Key} object, but they are such
 * that the {@link TinkProtoKeysetFormat} can be easily obtained from it.
 */
@Immutable
public final class ProtoKeySerialization {
  /**
   * An enum describing the key material type. Corresponds to the proto enum {@link
   * com.google.crypto.tink.KeyData.KeyMaterialType}.
   */
  @Immutable
  public static final class KeyMaterialType {
    public static final KeyMaterialType UNKNOWN_KEY_MATERIAL_TYPE =
        new KeyMaterialType("UNKNOWN_KEY_MATERIAL_TYPE");
    public static final KeyMaterialType SYMMETRIC = new KeyMaterialType("SYMMETRIC");
    public static final KeyMaterialType ASYMMETRIC_PRIVATE =
        new KeyMaterialType("ASYMMETRIC_PRIVATE");
    public static final KeyMaterialType ASYMMETRIC_PUBLIC =
        new KeyMaterialType("ASYMMETRIC_PUBLIC");
    public static final KeyMaterialType REMOTE = new KeyMaterialType("REMOTE");

    private final String name;

    private KeyMaterialType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /**
   * An enum describing the how to prefix signatures and ciphertexts. The concrete interpretation
   * will depend on the primitive and the key type.
   */
  @Immutable
  public static final class OutputPrefixType {
    public static final OutputPrefixType UNKNOWN_PREFIX = new OutputPrefixType("UNKNOWN_PREFIX");
    public static final OutputPrefixType TINK = new OutputPrefixType("TINK");
    public static final OutputPrefixType LEGACY = new OutputPrefixType("LEGACY");
    public static final OutputPrefixType RAW = new OutputPrefixType("RAW");
    public static final OutputPrefixType CRUNCHY = new OutputPrefixType("CRUNCHY");
    public static final OutputPrefixType WITH_ID_REQUIREMENT =
        new OutputPrefixType("WITH_ID_REQUIREMENT");

    private final String name;

    private OutputPrefixType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private final String typeUrl;
  private final ByteString value;
  private final KeyMaterialType keyMaterialType;
  private final OutputPrefixType outputPrefixType;
  @Nullable private final Integer idRequirementOrNull;

  /**
   * Creates new ProtoKeySerialization objects.
   *
   * <p>Throws an exception if (idRequirement == null) != (outputPrefixType == RAW) or if typeUrl
   * does not consist entirely of ASCII characters.
   */
  public static ProtoKeySerialization create(
      String typeUrl,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null && outputPrefixType.equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException("Cannot set idRequirement for OutputPrefixType RAW");
    }
    if (idRequirement == null && !outputPrefixType.equals(OutputPrefixType.RAW)) {
      throw new GeneralSecurityException(
          "Cannot have null idRequirement unless OutputPrefixType is RAW");
    }
    for (int i = 0; i < typeUrl.length(); ++i) {
      char c = typeUrl.charAt(i);
      if (c < '!' || c > '~') {
        throw new GeneralSecurityException(
            "typeURL " + typeUrl + " contains non-ascii character at position " + i);
      }
    }
    return new ProtoKeySerialization(
        typeUrl, value, keyMaterialType, outputPrefixType, idRequirement);
  }

  private ProtoKeySerialization(
      String typeUrl,
      ByteString value,
      KeyMaterialType keyMaterialType,
      OutputPrefixType outputPrefixType,
      @Nullable Integer idRequirementOrNull) {
    this.typeUrl = typeUrl;
    this.value = value;
    this.keyMaterialType = keyMaterialType;
    this.outputPrefixType = outputPrefixType;
    this.idRequirementOrNull = idRequirementOrNull;
  }

  public String getTypeUrl() {
    return typeUrl;
  }

  public ByteString getValue() {
    return value;
  }

  public KeyMaterialType getKeyMaterialType() {
    return keyMaterialType;
  }

  public OutputPrefixType getOutputPrefixType() {
    return outputPrefixType;
  }

  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirementOrNull;
  }
}
