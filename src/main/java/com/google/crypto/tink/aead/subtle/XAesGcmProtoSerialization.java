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

package com.google.crypto.tink.aead.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.XAesGcmKey;
import com.google.crypto.tink.aead.XAesGcmParameters;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Public Proto Serialization for {@link XAesGcmKey} and {@link XAesGcmParameters}. */
@AccessesPartialKey
public final class XAesGcmProtoSerialization {

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoParametersSerialization serializeParameters(XAesGcmParameters parameters)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.XAesGcmProtoSerialization.serializeParameters(
        parameters);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static ProtoKeySerialization serializeKey(XAesGcmKey key, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.XAesGcmProtoSerialization.serializeKey(key, access);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static XAesGcmParameters parseParameters(ProtoParametersSerialization serialization)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.XAesGcmProtoSerialization.parseParameters(
        serialization);
  }

  @RestrictedApi(
      explanation =
          "LowLevelCryptoCaller APIs are useful for implementing protocols, or higher level"
              + " cryptographic primitives. However, most users should use Keyset APIs in order to"
              + " be prepared for key rotation",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {LowLevelCryptoCaller.class})
  public static XAesGcmKey parseKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.internal.XAesGcmProtoSerialization.parseKey(
        serialization, access);
  }

  private XAesGcmProtoSerialization() {}
}
