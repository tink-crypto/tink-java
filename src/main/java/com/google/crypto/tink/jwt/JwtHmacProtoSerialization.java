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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ParametersParser;
import com.google.crypto.tink.internal.ParametersSerializer;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link JwtHmacKey} objects and {@link JwtHmacParameters} objects.
 */
@AccessesPartialKey
@LowLevelCryptoCaller
final class JwtHmacProtoSerialization {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.JwtHmacKey";

  private static final ParametersSerializer<JwtHmacParameters> PARAMETERS_SERIALIZER =
      ParametersSerializer.create(
          com.google.crypto.tink.jwt.subtle.JwtHmacProtoSerialization::serializeParameters,
          JwtHmacParameters.class);

  private static final ParametersParser PARAMETERS_PARSER =
      ParametersParser.create(
          com.google.crypto.tink.jwt.subtle.JwtHmacProtoSerialization::parseParameters, TYPE_URL);

  private static final KeySerializer<JwtHmacKey> KEY_SERIALIZER =
      KeySerializer.create(
          com.google.crypto.tink.jwt.subtle.JwtHmacProtoSerialization::serializeKey,
          JwtHmacKey.class);

  private static final KeyParser KEY_PARSER =
      KeyParser.create(
          com.google.crypto.tink.jwt.subtle.JwtHmacProtoSerialization::parseKey, TYPE_URL);

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

  private JwtHmacProtoSerialization() {}
}
