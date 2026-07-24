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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link HpkePrivateKey}, {@link HpkePublicKey}, and {@link
 * HpkeParameters} objects.
 */
@AccessesPartialKey
@LowLevelCryptoCaller
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HpkeProtoSerialization {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";

  private static final ParametersSerializer<HpkeParameters> PARAMETERS_SERIALIZER =
      ParametersSerializer.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::serializeParameters,
          HpkeParameters.class);

  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::parseParameters,
          PRIVATE_TYPE_URL);

  private static final KeySerializer<HpkePublicKey> PUBLIC_KEY_SERIALIZER =
      KeySerializer.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::serializePublicKey,
          HpkePublicKey.class);

  private static final KeyParser PUBLIC_KEY_PARSER =
      KeyParser.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::parsePublicKey,
          PUBLIC_TYPE_URL);

  private static final KeySerializer<HpkePrivateKey> PRIVATE_KEY_SERIALIZER =
      KeySerializer.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::serializePrivateKey,
          HpkePrivateKey.class);

  private static final KeyParser PRIVATE_KEY_PARSER =
      KeyParser.create(
          com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization::parsePrivateKey,
          PRIVATE_TYPE_URL);

  /**
   * Registers previously defined parser/serializer objects into a global, mutable registry.
   * Registration is public to enable custom configurations.
   */
  public static void register() throws GeneralSecurityException {
    register(MutableSerializationRegistry.globalInstance());
  }

  /** Registers previously defined parser/serializer objects into a given registry. */
  public static void register(MutableSerializationRegistry registry)
      throws GeneralSecurityException {
    registry.registerParametersSerializer(PARAMETERS_SERIALIZER);
    registry.registerParametersParser(PARAMETERS_PARSER);
    registry.registerKeySerializer(PUBLIC_KEY_SERIALIZER);
    registry.registerKeyParser(PUBLIC_KEY_PARSER);
    registry.registerKeySerializer(PRIVATE_KEY_SERIALIZER);
    registry.registerKeyParser(PRIVATE_KEY_PARSER);
  }

  private HpkeProtoSerialization() {}
}
