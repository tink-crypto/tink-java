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

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Implements a Parameters object for legacy types where no actual Parameters object is present. */
@Immutable
public final class LegacyProtoParameters extends Parameters {
  private final ProtoParametersSerialization serialization;

  /** Creates a new LegacyProtoParameters object. */
  public LegacyProtoParameters(ProtoParametersSerialization serialization) {
    this.serialization = serialization;
  }

  @Override
  public boolean hasIdRequirement() {
    return !serialization.getOutputPrefixType().equals(OutputPrefixType.RAW);
  }

  /** returns the serialization which was used to create this object. */
  public ProtoParametersSerialization getSerialization() {
    return serialization;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyProtoParameters)) {
      return false;
    }
    ProtoParametersSerialization other = ((LegacyProtoParameters) o).serialization;
    return serialization.getOutputPrefixType().equals(other.getOutputPrefixType())
        && serialization.getTypeUrl().equals(other.getTypeUrl())
        && serialization.getValue().equals(other.getValue());
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        serialization.getTypeUrl(),
        serialization.getValue(),
        serialization.getOutputPrefixType(),
        serialization.getObjectIdentifier());
  }

  @Override
  public String toString() {
    return String.format(
        "(typeUrl=%s, outputPrefixType=%s)",
        serialization.getTypeUrl(), serialization.getOutputPrefixType());
  }
}
