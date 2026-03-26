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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Private key for the composite ML-DSA signatures. */
@Immutable
public final class CompositeMlDsaPrivateKey extends SignaturePrivateKey {
  private final CompositeMlDsaPublicKey publicKey;
  private final MlDsaPrivateKey mlDsaPrivateKey;
  private final SignaturePrivateKey classicalPrivateKey;

  /** Builder for CompositeMlDsaPrivateKey. */
  public static final class Builder {
    @Nullable private CompositeMlDsaParameters parameters = null;
    @Nullable private MlDsaPrivateKey mlDsaPrivateKey = null;
    @Nullable private SignaturePrivateKey classicalPrivateKey = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(CompositeMlDsaParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setMlDsaPrivateKey(MlDsaPrivateKey mlDsaPrivateKey) {
      this.mlDsaPrivateKey = mlDsaPrivateKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setClassicalPrivateKey(SignaturePrivateKey classicalPrivateKey) {
      this.classicalPrivateKey = classicalPrivateKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    @AccessesPartialKey
    public CompositeMlDsaPrivateKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Parameters are not set");
      }
      if (mlDsaPrivateKey == null) {
        throw new GeneralSecurityException("ML-DSA private key is not set");
      }
      if (classicalPrivateKey == null) {
        throw new GeneralSecurityException("Classical private key is not set");
      }
      if (parameters.hasIdRequirement() && idRequirement == null) {
        throw new GeneralSecurityException("ID requirement is not set");
      }
      if (!parameters.hasIdRequirement() && idRequirement != null) {
        throw new GeneralSecurityException("ID requirement is set");
      }

      CompositeMlDsaPublicKey publicKey =
          CompositeMlDsaPublicKey.builder()
              .setParameters(parameters)
              .setMlDsaPublicKey(mlDsaPrivateKey.getPublicKey())
              .setClassicalPublicKey(classicalPrivateKey.getPublicKey())
              .setIdRequirement(idRequirement)
              .build();

      return new CompositeMlDsaPrivateKey(publicKey, mlDsaPrivateKey, classicalPrivateKey);
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

  private CompositeMlDsaPrivateKey(
      CompositeMlDsaPublicKey publicKey,
      MlDsaPrivateKey mlDsaPrivateKey,
      SignaturePrivateKey classicalPrivateKey) {
    this.publicKey = publicKey;
    this.mlDsaPrivateKey = mlDsaPrivateKey;
    this.classicalPrivateKey = classicalPrivateKey;
  }

  @Override
  public CompositeMlDsaPublicKey getPublicKey() {
    return publicKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public MlDsaPrivateKey getMlDsaPrivateKey() {
    return mlDsaPrivateKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SignaturePrivateKey getClassicalPrivateKey() {
    return classicalPrivateKey;
  }

  @Override
  public CompositeMlDsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public boolean equalsKey(Key other) {
    if (!(other instanceof CompositeMlDsaPrivateKey)) {
      return false;
    }
    CompositeMlDsaPrivateKey that = (CompositeMlDsaPrivateKey) other;
    return publicKey.equalsKey(that.publicKey)
        && mlDsaPrivateKey.equalsKey(that.mlDsaPrivateKey)
        && classicalPrivateKey.equalsKey(that.classicalPrivateKey);
  }
}
