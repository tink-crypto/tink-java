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
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Methods to serialize and parse {@link EcdsaPrivateKey}, {@link EcdsaPublicKey}, and {@link
 * EcdsaParameters} objects.
 */
@AccessesPartialKey
public final class EcdsaProtoSerialization {

  private EcdsaProtoSerialization() {}

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static ProtoParametersSerialization serializeParameters(EcdsaParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.serializeParameters(
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
      EcdsaPublicKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.serializePublicKey(
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
      EcdsaPrivateKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.serializePrivateKey(
        key, access);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static EcdsaParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.parseParameters(
        serialization);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static EcdsaPublicKey parsePublicKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.parsePublicKey(
        serialization, access);
  }

  @RestrictedApi(
      explanation = "Accessing subtle serialization APIs directly is restricted.",
      link = "https://tink.keystore.google/errorprone/RestrictedApi",
      allowedOnPath = ".*",
      allowlistAnnotations = {
        LowLevelCryptoCaller.class,
      })
  public static EcdsaPrivateKey parsePrivateKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.internal.EcdsaProtoSerialization.parsePrivateKey(
        serialization, access);
  }
}
