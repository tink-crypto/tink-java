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

import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * An object implementing this interface represents a collection of algorithms that a user wants
 * Tink to understand. For most users, one of the predefined {@link Configuration} objects is to be
 * used at primitive creation time.
 */
public interface Configuration {
  /**
   * Creates a primitive from a given keyset handle.
   *
   * <p>Usually, users should call {@code keysetHandle.getPrimitive(config, clazz);} instead.
   */
  default <P> P createPrimitive(KeysetHandleInterface keysetHandle, Class<P> clazz)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("createPrimitive is unimplemented");
  }

  /**
   * Returns a generic object.
   *
   * <p>Tink uses {@code getOrNull} to return objects which not all configs may implement, or where
   * we do not want a dependency on the class from here. For example, most configs support getting a
   * {@link ProtoKeySerializer} object here, which can be used to serialized keysets in proto
   * format. Not naming the class here allows to ensure that {@code Configuration} does not depend
   * on the protobuf library.
   */
  @Nullable
  default <P> P getOrNull(Class<P> clazz) {
    return null;
  }

  /**
   * Creates a new key from a parameters object.
   *
   * <p>Most users should not use this function. Instead, they will use the configuration object on
   * the {@code KeysetHandle.Builder}. For example:
   *
   * <pre>{@code
   * KeysetHandle handle =
   *     KeysetHandle.newBuilder()
   *         .addEntry(
   *             KeysetHandle.generateEntryFromParameters(params)
   *                 .withFixedId(42)
   *                 .makePrimary())
   *         .setConfiguration(config)
   *         .build();
   * }</pre>
   */
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  default Key createKey(Parameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("createKey is unimplemented");
  }
}
