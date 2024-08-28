// Copyright 2024 Google LLC
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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Represents an X-AES-GCM key used for computing AEAD. */
@Immutable
public final class XAesGcmKey extends AeadKey {
  private final XAesGcmParameters parameters;
  private final SecretBytes keyBytes;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private XAesGcmKey(
      XAesGcmParameters parameters,
      SecretBytes keyBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.keyBytes = keyBytes;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  private static Bytes getOutputPrefix(
      XAesGcmParameters parameters, @Nullable Integer idRequirement) {
    if (parameters.getVariant() == XAesGcmParameters.Variant.NO_PREFIX) {
      return OutputPrefixUtil.EMPTY_PREFIX;
    }
    if (parameters.getVariant() == XAesGcmParameters.Variant.CRUNCHY) {
      return OutputPrefixUtil.getLegacyOutputPrefix(idRequirement);
    }
    if (parameters.getVariant() == XAesGcmParameters.Variant.TINK) {
      return OutputPrefixUtil.getTinkOutputPrefix(idRequirement);
    }
    throw new IllegalStateException("Unknown Variant: " + parameters.getVariant());
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static XAesGcmKey create(
      XAesGcmParameters parameters, SecretBytes secretBytes, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (parameters.getVariant() != XAesGcmParameters.Variant.NO_PREFIX && idRequirement == null) {
      throw new GeneralSecurityException(
          "For given Variant "
              + parameters.getVariant()
              + " the value of idRequirement must be non-null");
    }
    if (parameters.getVariant() == XAesGcmParameters.Variant.NO_PREFIX && idRequirement != null) {
      throw new GeneralSecurityException(
          "For given Variant NO_PREFIX the value of idRequirement must be null");
    }
    if (secretBytes.size() != 32) {
      throw new GeneralSecurityException(
          "XAesGcmKey key must be constructed with key of length 32 bytes, not "
              + secretBytes.size());
    }
    return new XAesGcmKey(
        parameters, secretBytes, getOutputPrefix(parameters, idRequirement), idRequirement);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getKeyBytes() {
    return keyBytes;
  }

  @Override
  public XAesGcmParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof XAesGcmKey)) {
      return false;
    }
    XAesGcmKey that = (XAesGcmKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return that.parameters.equals(parameters)
        && that.keyBytes.equalsSecretBytes(keyBytes)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
