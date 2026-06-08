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

import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;

/**
 * Represents a {@code Parameters} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoParametersSerialization} objects fully describe a {@code Parameters} object, but
 * tailored for protocol buffer serialization.
 */
@Immutable
public final class ProtoParametersSerialization implements Serialization {
  private final ByteString value;
  private final Bytes objectIdentifier;
  private final String typeUrl;
  private final OutputPrefixType outputPrefixType;

  private ProtoParametersSerialization(
      ByteString value, String typeUrl, Bytes objectIdentifier, OutputPrefixType outputPrefixType) {
    this.value = value;
    this.typeUrl = typeUrl;
    this.objectIdentifier = objectIdentifier;
    this.outputPrefixType = outputPrefixType;
  }

  /**
   * Creates a new {@code ProtoParametersSerialization} object from the individual parts.
   *
   * <p>Note: the given typeUrl must be valid and must not contain invalid characters.
   */
  public static ProtoParametersSerialization create(
      String typeUrl, OutputPrefixType outputPrefixType, ByteString value)
      throws GeneralSecurityException {
    return new ProtoParametersSerialization(
        value, typeUrl, checkedToBytesFromPrintableAscii(typeUrl), outputPrefixType);
  }


  public OutputPrefixType getOutputPrefixType() {
    return outputPrefixType;
  }

  /** The typeUrl. */
  @Override
  public Bytes getObjectIdentifier() {
    return objectIdentifier;
  }

  /** The typeUrl. */
  public String getTypeUrl() {
    return typeUrl;
  }

  /** The value. */
  public ByteString getValue() {
    return value;
  }
}
