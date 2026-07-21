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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;

/** JwtMlDsaPublicKey represents the public portion of JWT ML-DSA keys. */
@Immutable
public final class JwtMlDsaPublicKey extends JwtSignaturePublicKey {
  private final JwtMlDsaParameters parameters;
  private final MlDsaPublicKey mlDsaPublicKey;
  private final Optional<String> kid;
  private final Optional<Integer> idRequirement;

  /** Builder for JwtMlDsaPublicKey. */
  public static class Builder {
    private Optional<JwtMlDsaParameters> parameters = Optional.empty();
    private Optional<Bytes> publicKeyBytes = Optional.empty();
    private Optional<Integer> idRequirement = Optional.empty();
    private Optional<String> customKid = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(JwtMlDsaParameters parameters) {
      this.parameters = Optional.of(parameters);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicKeyBytes(Bytes publicKeyBytes) {
      this.publicKeyBytes = Optional.of(publicKeyBytes);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(Integer idRequirement) {
      this.idRequirement = Optional.of(idRequirement);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setCustomKid(String customKid) {
      this.customKid = Optional.of(customKid);
      return this;
    }

    private Optional<String> computeKid() throws GeneralSecurityException {
      if (parameters
          .get()
          .getKidStrategy()
          .equals(JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException(
              "customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
        }
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement.get()).array();
        return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
      }
      if (parameters.get().getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.CUSTOM)) {
        if (!customKid.isPresent()) {
          throw new GeneralSecurityException("customKid needs to be set for KidStrategy CUSTOM");
        }
        return customKid;
      }
      if (parameters.get().getKidStrategy().equals(JwtMlDsaParameters.KidStrategy.IGNORED)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException("customKid must not be set for KidStrategy IGNORED");
        }
        return Optional.empty();
      }
      throw new IllegalStateException("Unknown kid strategy");
    }

    private static MlDsaParameters.MlDsaInstance getInstance(JwtMlDsaParameters parameters)
        throws GeneralSecurityException {
      if (parameters.getAlgorithm().equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
        return MlDsaParameters.MlDsaInstance.ML_DSA_44;
      }
      if (parameters.getAlgorithm().equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
        return MlDsaParameters.MlDsaInstance.ML_DSA_65;
      }
      if (parameters.getAlgorithm().equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
        return MlDsaParameters.MlDsaInstance.ML_DSA_87;
      }
      throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
    }

    @AccessesPartialKey
    public JwtMlDsaPublicKey build() throws GeneralSecurityException {
      if (!parameters.isPresent()) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }
      if (!publicKeyBytes.isPresent()) {
        throw new GeneralSecurityException("Cannot build without public key bytes");
      }
      if (parameters.get().hasIdRequirement() && !idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }
      if (!parameters.get().hasIdRequirement() && idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }

      MlDsaParameters mlDsaParameters =
          MlDsaParameters.create(getInstance(parameters.get()), MlDsaParameters.Variant.NO_PREFIX);
      MlDsaPublicKey mlDsaPublicKey =
          MlDsaPublicKey.builder()
              .setParameters(mlDsaParameters)
              .setSerializedPublicKey(publicKeyBytes.get())
              .build();
      return new JwtMlDsaPublicKey(parameters.get(), mlDsaPublicKey, computeKid(), idRequirement);
    }
  }

  private JwtMlDsaPublicKey(
      JwtMlDsaParameters parameters,
      MlDsaPublicKey mlDsaPublicKey,
      Optional<String> kid,
      Optional<Integer> idRequirement) {
    this.parameters = parameters;
    this.mlDsaPublicKey = mlDsaPublicKey;
    this.kid = kid;
    this.idRequirement = idRequirement;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Optional<String> getKid() {
    return kid;
  }

  @Nullable
  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement.orElse(null);
  }

  @Override
  public JwtMlDsaParameters getParameters() {
    return parameters;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtMlDsaPublicKey)) {
      return false;
    }
    JwtMlDsaPublicKey that = (JwtMlDsaPublicKey) o;
    return that.parameters.equals(parameters)
        && that.mlDsaPublicKey.equalsKey(mlDsaPublicKey)
        && that.kid.equals(kid);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public MlDsaPublicKey getMlDsaPublicKey() {
    return mlDsaPublicKey;
  }
}
