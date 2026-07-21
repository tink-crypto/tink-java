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

package com.google.crypto.tink;

import com.google.crypto.tink.internal.ProtoConversions;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.errorprone.annotations.InlineMe;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Functions to parse and serialize Parameters in Tink's binary format based on Protobufs. */
public final class TinkProtoParametersFormat {
  /**
   * Serializes a Parameters object into a byte[] according to Tink's binary format, using the
   * {@link RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkProtoParametersFormat.serialize(parameters, RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkProtoParametersFormat"
      })
  @Deprecated // This function should be inlined.
  @LowLevelCryptoCaller
  public static byte[] serialize(Parameters parameters) throws GeneralSecurityException {
    return serialize(parameters, RegistryConfiguration.get());
  }

  /**
   * Serializes a Parameters object into a byte[] according to Tink's binary format, using the
   * provided {@link Configuration}.
   */
  @LowLevelCryptoCaller
  public static byte[] serialize(Parameters parameters, Configuration configuration)
      throws GeneralSecurityException {
    @Nullable ProtoKeySerializer serializer = configuration.getOrNull(ProtoKeySerializer.class);
    if (serializer == null) {
      throw new GeneralSecurityException(
          "Provided configuration cannot be used to serialize in ProtoParametersFormat.");
    }
    ProtoParametersSerialization serialization = serializer.serializeParameters(parameters);
    return KeyTemplate.newBuilder()
        .setTypeUrl(serialization.getTypeUrl())
        .setValue(serialization.getValue())
        .setOutputPrefixType(ProtoConversions.toProto(serialization.getOutputPrefixType()))
        .build()
        .toByteArray();
  }

  /**
   * Parses a byte[] into a Parameters object according to Tink's binary format, using the
   * {@link RegistryConfiguration}.
   *
   * @deprecated This function should be inlined.
   */
  @InlineMe(
      replacement =
          "TinkProtoParametersFormat.parse(serializedParameters, RegistryConfiguration.get())",
      imports = {
        "com.google.crypto.tink.RegistryConfiguration",
        "com.google.crypto.tink.TinkProtoParametersFormat"
      })
  @Deprecated // This function should be inlined.
  @LowLevelCryptoCaller
  public static Parameters parse(byte[] serializedParameters) throws GeneralSecurityException {
    return parse(serializedParameters, RegistryConfiguration.get());
  }

  /**
   * Parses a byte[] into a Parameters object according to Tink's binary format, using the
   * provided {@link Configuration}.
   */
  @LowLevelCryptoCaller
  public static Parameters parse(byte[] serializedParameters, Configuration configuration)
      throws GeneralSecurityException {
    @Nullable ProtoKeySerializer serializer = configuration.getOrNull(ProtoKeySerializer.class);
    if (serializer == null) {
      throw new GeneralSecurityException(
          "Provided configuration cannot be used to parse ProtoParametersFormat.");
    }

    KeyTemplate t;
    try {
      t = KeyTemplate.parseFrom(serializedParameters, ExtensionRegistryLite.getEmptyRegistry());
    } catch (IOException e) {
      throw new GeneralSecurityException("Failed to parse proto", e);
    }
    return serializer.parseParameters(
        ProtoParametersSerialization.create(
            t.getTypeUrl(), ProtoConversions.fromProto(t.getOutputPrefixType()), t.getValue()));
  }

  private TinkProtoParametersFormat() {}
}
