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
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/** Public key for composite ML-DSA signatures. */
@Immutable
public final class CompositeMlDsaPublicKey extends SignaturePublicKey {
  private static final Map<CompositeMlDsaParameters.ClassicalAlgorithm, SignatureParameters>
      supportedClassicalParameters = createSupportedClassicalParameters();

  private static Map<CompositeMlDsaParameters.ClassicalAlgorithm, SignatureParameters>
      createSupportedClassicalParameters() {
    try {
      return Map.of(
          CompositeMlDsaParameters.ClassicalAlgorithm.ED25519,
          Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX),
          CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P256,
          EcdsaParameters.builder()
              .setHashType(EcdsaParameters.HashType.SHA256)
              .setCurveType(EcdsaParameters.CurveType.NIST_P256)
              .setVariant(EcdsaParameters.Variant.NO_PREFIX)
              .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P384,
          EcdsaParameters.builder()
              .setHashType(EcdsaParameters.HashType.SHA384)
              .setCurveType(EcdsaParameters.CurveType.NIST_P384)
              .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .setVariant(EcdsaParameters.Variant.NO_PREFIX)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P521,
          EcdsaParameters.builder()
              .setHashType(EcdsaParameters.HashType.SHA512)
              .setCurveType(EcdsaParameters.CurveType.NIST_P521)
              .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .setVariant(EcdsaParameters.Variant.NO_PREFIX)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.RSA3072_PSS,
          RsaSsaPssParameters.builder()
              .setModulusSizeBits(3072)
              .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
              .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
              .setSaltLengthBytes(32)
              .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.RSA4096_PSS,
          RsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
              .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
              .setSaltLengthBytes(48)
              .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.RSA3072_PKCS1,
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(3072)
              .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .build(),
          CompositeMlDsaParameters.ClassicalAlgorithm.RSA4096_PKCS1,
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .build());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Could not create supported classical parameters", e);
    }
  }

  private final CompositeMlDsaParameters parameters;
  private final MlDsaPublicKey mlDsaPublicKey;
  private final SignaturePublicKey classicalPublicKey;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  /** Builder for CompositeMlDsaPublicKey. */
  public static final class Builder {
    @Nullable private CompositeMlDsaParameters parameters = null;
    @Nullable private MlDsaPublicKey mlDsaPublicKey = null;
    @Nullable private SignaturePublicKey classicalPublicKey = null;
    @Nullable private Integer idRequirement = null;

    @CanIgnoreReturnValue
    public Builder setParameters(CompositeMlDsaParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setMlDsaPublicKey(MlDsaPublicKey mlDsaPublicKey) {
      this.mlDsaPublicKey = mlDsaPublicKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setClassicalPublicKey(SignaturePublicKey classicalPublicKey) {
      this.classicalPublicKey = classicalPublicKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      // We do sanity checking before calling this method, thus preventing the NPEs.
      if (parameters.getVariant() == CompositeMlDsaParameters.Variant.NO_PREFIX) {
        return OutputPrefixUtil.EMPTY_PREFIX;
      }
      if (parameters.getVariant() == CompositeMlDsaParameters.Variant.TINK) {
        return OutputPrefixUtil.getTinkOutputPrefix(idRequirement);
      }
      throw new IllegalStateException(
          "Unknown CompositeMlDsaParameters.Variant: " + parameters.getVariant());
    }

    public CompositeMlDsaPublicKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Parameters are not set");
      }
      if (mlDsaPublicKey == null) {
        throw new GeneralSecurityException("ML-DSA public key is not set");
      }
      if (classicalPublicKey == null) {
        throw new GeneralSecurityException("Classical public key is not set");
      }
      if (parameters.hasIdRequirement() && idRequirement == null) {
        throw new GeneralSecurityException("ID requirement is not set");
      }
      if (!parameters.hasIdRequirement() && idRequirement != null) {
        throw new GeneralSecurityException("ID requirement is set");
      }
      if (mlDsaPublicKey.getParameters().getVariant() != MlDsaParameters.Variant.NO_PREFIX) {
        throw new GeneralSecurityException(
            "ML-DSA variant must be NO_PREFIX, found "
                + mlDsaPublicKey.getParameters().getVariant()
                + " instead");
      }
      if (!((parameters.getMlDsaInstance() == CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65
              && mlDsaPublicKey.getParameters().getMlDsaInstance()
                  == MlDsaParameters.MlDsaInstance.ML_DSA_65)
          || (parameters.getMlDsaInstance() == CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87
              && mlDsaPublicKey.getParameters().getMlDsaInstance()
                  == MlDsaParameters.MlDsaInstance.ML_DSA_87))) {
        throw new GeneralSecurityException("ML-DSA instance does not match");
      }
      // From here on, we rely on the fact that CompositeMlDsaParameters builder verified that the
      // classical algorithm matches the ML-DSA instance.
      if (!supportedClassicalParameters.containsKey(parameters.getClassicalAlgorithm())) {
        throw new GeneralSecurityException("Unknown classical algorithm");
      }
      if (!classicalPublicKey
          .getParameters()
          .equals(supportedClassicalParameters.get(parameters.getClassicalAlgorithm()))) {
        throw new GeneralSecurityException("Classical algorithm does not match");
      }

      Bytes outputPrefix = getOutputPrefix();
      return new CompositeMlDsaPublicKey(
          parameters, mlDsaPublicKey, classicalPublicKey, outputPrefix, idRequirement);
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

  private CompositeMlDsaPublicKey(
      CompositeMlDsaParameters parameters,
      MlDsaPublicKey mlDsaPublicKey,
      SignaturePublicKey classicalPublicKey,
      Bytes outputPrefix,
      Integer idRequirement) {
    this.parameters = parameters;
    this.mlDsaPublicKey = mlDsaPublicKey;
    this.classicalPublicKey = classicalPublicKey;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  /** The getters. */
  public MlDsaPublicKey getMlDsaPublicKey() {
    return mlDsaPublicKey;
  }

  public SignaturePublicKey getClassicalPublicKey() {
    return classicalPublicKey;
  }

  /** The necessary overridden methods. */
  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public CompositeMlDsaParameters getParameters() {
    return parameters;
  }

  @Nullable
  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof CompositeMlDsaPublicKey)) {
      return false;
    }
    CompositeMlDsaPublicKey other = (CompositeMlDsaPublicKey) o;
    return parameters.equals(other.parameters)
        && mlDsaPublicKey.equals(other.mlDsaPublicKey)
        && classicalPublicKey.equals(other.classicalPublicKey)
        && Objects.equals(idRequirement, other.idRequirement);
  }
}
