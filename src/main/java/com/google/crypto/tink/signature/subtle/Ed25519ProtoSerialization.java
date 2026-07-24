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

package com.google.crypto.tink.signature.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link Ed25519PrivateKey}, {@link Ed25519PublicKey}, and {@link
 * Ed25519Parameters} objects.
 */
@AccessesPartialKey
public final class Ed25519ProtoSerialization {

  private Ed25519ProtoSerialization() {}

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static ProtoParametersSerialization serializeParameters(Ed25519Parameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.serializeParameters(
        parameters);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static ProtoKeySerialization serializePublicKey(
      Ed25519PublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.serializePublicKey(
        key, access);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static ProtoKeySerialization serializePrivateKey(
      Ed25519PrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.serializePrivateKey(
        key, access);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static Ed25519Parameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.parseParameters(
        serialization);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static Ed25519PublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.parsePublicKey(
        serialization, access);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static Ed25519PrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization.parsePrivateKey(
        serialization, access);
  }
}
