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
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link EciesParameters}, {@link EciesPrivateKey}, and {@link
 * EciesPublicKey} objects.
 */
@AccessesPartialKey
public final class EciesProtoSerialization {

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoParametersSerialization serializeParameters(EciesParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.serializeParameters(
        parameters);
  }

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePublicKey(
      EciesPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.serializePublicKey(
        key, access);
  }

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializePrivateKey(
      EciesPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.serializePrivateKey(
        key, access);
  }

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static EciesParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.parseParameters(
        serialization);
  }

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static EciesPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.parsePublicKey(
        serialization, access);
  }

  @LowLevelCryptoCaller
  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static EciesPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.hybrid.internal.EciesProtoSerialization.parsePrivateKey(
        serialization, access);
  }

  private EciesProtoSerialization() {}
}
