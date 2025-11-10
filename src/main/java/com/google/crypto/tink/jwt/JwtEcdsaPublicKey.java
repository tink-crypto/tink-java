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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Optional;
import javax.annotation.Nullable;

/** JwtEcdsaPublicKey represents the public portion of JWT ECDSA keys. */
@Immutable
public final class JwtEcdsaPublicKey extends JwtSignaturePublicKey {
  private final JwtEcdsaParameters parameters;

  private final EcdsaPublicKey ecdsaPublicKey;

  private final Optional<String> kid;
  private final Optional<Integer> idRequirement;

  /** Builder for JwtEcdsaPublicKey. */
  public static class Builder {
    private Optional<JwtEcdsaParameters> parameters = Optional.empty();
    private Optional<ECPoint> publicPoint = Optional.empty();
    private Optional<Integer> idRequirement = Optional.empty();
    private Optional<String> customKid = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(JwtEcdsaParameters parameters) {
      this.parameters = Optional.of(parameters);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicPoint(ECPoint publicPoint) {
      this.publicPoint = Optional.of(publicPoint);
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
          .equals(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException(
              "customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
        }
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement.get()).array();
        return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
      }
      if (parameters.get().getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.CUSTOM)) {
        if (!customKid.isPresent()) {
          throw new GeneralSecurityException("customKid needs to be set for KidStrategy CUSTOM");
        }
        return customKid;
      }
      if (parameters.get().getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.IGNORED)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException("customKid must not be set for KidStrategy IGNORED");
        }
        return Optional.empty();
      }
      throw new IllegalStateException("Unknown kid strategy");
    }

    private static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
        throws GeneralSecurityException {
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
        return EcdsaParameters.CurveType.NIST_P256;
      }
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
        return EcdsaParameters.CurveType.NIST_P384;
      }
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
        return EcdsaParameters.CurveType.NIST_P521;
      }
      throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
    }

    private static EcdsaParameters.HashType getHashType(JwtEcdsaParameters parameters)
        throws GeneralSecurityException {
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
        return EcdsaParameters.HashType.SHA256;
      }
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
        return EcdsaParameters.HashType.SHA384;
      }
      if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
        return EcdsaParameters.HashType.SHA512;
      }
      throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
    }

    @AccessesPartialKey
    public JwtEcdsaPublicKey build() throws GeneralSecurityException {
      if (!parameters.isPresent()) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }
      if (!publicPoint.isPresent()) {
        throw new GeneralSecurityException("Cannot build without public point");
      }
      if (parameters.get().hasIdRequirement() && !idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }
      if (!parameters.get().hasIdRequirement() && idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }

      EcdsaParameters ecdsaParameters =
          EcdsaParameters.builder()
              .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .setCurveType(getCurveType(parameters.get()))
              .setHashType(getHashType(parameters.get()))
              .build();
      EcdsaPublicKey ecdsaPublicKey =
          EcdsaPublicKey.builder()
              .setParameters(ecdsaParameters)
              .setPublicPoint(publicPoint.get())
              .build();
      return new JwtEcdsaPublicKey(parameters.get(), ecdsaPublicKey, computeKid(), idRequirement);
    }
  }

  private JwtEcdsaPublicKey(
      JwtEcdsaParameters parameters,
      EcdsaPublicKey ecdsaPublicKey,
      Optional<String> kid,
      Optional<Integer> idRequirement) {
    this.parameters = parameters;
    this.ecdsaPublicKey = ecdsaPublicKey;
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

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public ECPoint getPublicPoint() {
    return ecdsaPublicKey.getPublicPoint();
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
  public JwtEcdsaParameters getParameters() {
    return parameters;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtEcdsaPublicKey)) {
      return false;
    }
    JwtEcdsaPublicKey that = (JwtEcdsaPublicKey) o;
    return that.parameters.equals(parameters)
        && that.ecdsaPublicKey.equalsKey(ecdsaPublicKey)
        && that.kid.equals(kid);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  EcdsaPublicKey getEcdsaPublicKey() {
    return ecdsaPublicKey;
  }
}
