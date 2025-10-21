// Copyright 2025 Google LLC
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Public key for ML-DSA-65.
 */
public class MlDsaPublicKey extends SignaturePublicKey {

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;

  private final MlDsaParameters parameters;
  private final Bytes serializedPublicKey;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private MlDsaPublicKey(
      MlDsaParameters parameters,
      Bytes serializedPublicKey,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.serializedPublicKey = serializedPublicKey;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  /** Builder for MlDsaPublicKey. */
  public static class Builder {
    @Nullable private MlDsaParameters parameters = null;
    @Nullable private Bytes serializedPublicKey = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(MlDsaParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSerializedPublicKey(Bytes serializedPublicKey) {
      this.serializedPublicKey = serializedPublicKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      // We do sanity checking before calling this method, thus preventing the NPEs.
      if (parameters.getVariant() == MlDsaParameters.Variant.NO_PREFIX) {
        return OutputPrefixUtil.EMPTY_PREFIX;
      }
      if (parameters.getVariant() == MlDsaParameters.Variant.TINK) {
        return OutputPrefixUtil.getTinkOutputPrefix(idRequirement);
      }
      throw new IllegalStateException(
          "Unknown MlDsaParameters.Variant: " + parameters.getVariant());
    }

    public MlDsaPublicKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }
      if (parameters.getVariant() == MlDsaParameters.Variant.NO_PREFIX && idRequirement != null) {
        throw new GeneralSecurityException(
            "Id requirement present for parameters' variant NO_PREFIX");
      }
      if (parameters.getVariant() == MlDsaParameters.Variant.TINK && idRequirement == null) {
        throw new GeneralSecurityException("Id requirement missing for parameters' variant TINK");
      }

      if (serializedPublicKey == null) {
        throw new GeneralSecurityException("Cannot build without public key bytes");
      }
      if (parameters.getMlDsaInstance() != MlDsaInstance.ML_DSA_65) {
        throw new GeneralSecurityException(
            "Unknown ML-DSA instance; only ML-DSA-65 is currently supported");
      }
      if (serializedPublicKey.size() != MLDSA65_PUBLIC_KEY_BYTES) {
        throw new GeneralSecurityException("Incorrect public key size for ML-DSA-65");
      }

      Bytes outputPrefix = getOutputPrefix();
      return new MlDsaPublicKey(parameters, serializedPublicKey, outputPrefix, idRequirement);
    }
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public Bytes getSerializedPublicKey() {
    return serializedPublicKey;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public MlDsaParameters getParameters() {
    return parameters;
  }

  @Nullable
  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof MlDsaPublicKey)) {
      return false;
    }
    MlDsaPublicKey that = (MlDsaPublicKey) o;
    return that.parameters.equals(parameters)
        && that.serializedPublicKey.equals(serializedPublicKey)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
