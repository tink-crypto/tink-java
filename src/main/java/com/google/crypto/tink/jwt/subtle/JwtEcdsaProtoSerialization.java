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

package com.google.crypto.tink.jwt.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Public Proto Serialization for {@link JwtEcdsaPublicKey}, {@link JwtEcdsaPrivateKey}, and {@link
 * JwtEcdsaParameters}.
 */
@AccessesPartialKey
public final class JwtEcdsaProtoSerialization {

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoParametersSerialization serializeParameters(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.serializeParameters(
        parameters);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePublicKey(
      JwtEcdsaPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.serializePublicKey(
        key, access);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePrivateKey(
      JwtEcdsaPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.serializePrivateKey(
        key, access);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static JwtEcdsaParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.parseParameters(
        serialization);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static JwtEcdsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.parsePublicKey(
        serialization, access);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static JwtEcdsaPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization.parsePrivateKey(
        serialization, access);
  }

  private JwtEcdsaProtoSerialization() {}
}
