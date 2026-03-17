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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Parameters for the composite ML-DSA signatures. */
public final class CompositeMlDsaParameters extends SignatureParameters {
  /**
   * Describes details of the composite ML-DSA signature format.
   *
   * <p>The standard composite ML-DSA key is used for variant "NO_PREFIX". "TINK" adds a prefix to
   * every computation depending on the key id.
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant NO_PREFIX = new Variant("NO_PREFIX");

    private final String name;

    private Variant(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /**
   * Describes the parameters set of ML-DSA that is used.
   *
   * <p>ML-DSA-44 is not supported.
   */
  @Immutable
  public static final class MlDsaInstance {
    public static final MlDsaInstance ML_DSA_65 = new MlDsaInstance("ML_DSA_65");
    public static final MlDsaInstance ML_DSA_87 = new MlDsaInstance("ML_DSA_87");

    private final String name;

    private MlDsaInstance(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The classical algorithm used. */
  @Immutable
  public static final class ClassicalAlgorithm {
    public static final ClassicalAlgorithm ED25519 = new ClassicalAlgorithm("ED25519");
    public static final ClassicalAlgorithm ECDSA_P256 = new ClassicalAlgorithm("ECDSA_P256");
    public static final ClassicalAlgorithm ECDSA_P384 = new ClassicalAlgorithm("ECDSA_P384");
    public static final ClassicalAlgorithm ECDSA_P521 = new ClassicalAlgorithm("ECDSA_P521");
    public static final ClassicalAlgorithm RSA3072_PSS = new ClassicalAlgorithm("RSA3072_PSS");
    public static final ClassicalAlgorithm RSA4096_PSS = new ClassicalAlgorithm("RSA4096_PSS");
    public static final ClassicalAlgorithm RSA3072_PKCS1 = new ClassicalAlgorithm("RSA3072_PKCS1");
    public static final ClassicalAlgorithm RSA4096_PKCS1 = new ClassicalAlgorithm("RSA4096_PKCS1");

    private final String name;

    private ClassicalAlgorithm(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private final MlDsaInstance mlDsaInstance;
  private final ClassicalAlgorithm classicalAlgorithm;
  private final Variant variant;

  /**
   * Build a new CompositeMlDsaParameters instance. Note that the pre-hash type is defined uniquely
   * by the combination of the ML-DSA instance and the classical algorithm used, so we do not ask
   * the user to set it here (and it is also not a part of the protos).
   */
  public static final class Builder {
    private static final List<ClassicalAlgorithm> mlDsa65CompatibleClassicalAlgorithms =
        Arrays.asList(
            ClassicalAlgorithm.ED25519,
            ClassicalAlgorithm.ECDSA_P256,
            ClassicalAlgorithm.ECDSA_P384,
            ClassicalAlgorithm.RSA3072_PSS,
            ClassicalAlgorithm.RSA4096_PSS,
            ClassicalAlgorithm.RSA3072_PKCS1,
            ClassicalAlgorithm.RSA4096_PKCS1);
    private static final List<ClassicalAlgorithm> mlDsa87CompatibleClassicalAlgorithms =
        Arrays.asList(
            ClassicalAlgorithm.ECDSA_P384,
            ClassicalAlgorithm.ECDSA_P521,
            ClassicalAlgorithm.RSA3072_PSS,
            ClassicalAlgorithm.RSA4096_PSS);

    private MlDsaInstance mlDsaInstance = null;
    private ClassicalAlgorithm classicalAlgorithm = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setMlDsaInstance(MlDsaInstance mlDsaInstance) {
      this.mlDsaInstance = mlDsaInstance;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setClassicalAlgorithm(ClassicalAlgorithm classicalAlgorithm) {
      this.classicalAlgorithm = classicalAlgorithm;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    public CompositeMlDsaParameters build() throws GeneralSecurityException {
      if (mlDsaInstance == null) {
        throw new GeneralSecurityException("ML-DSA instance is not set");
      }
      if (classicalAlgorithm == null) {
        throw new GeneralSecurityException("Classical algorithm is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("Variant is not set");
      }
      if (mlDsaInstance == MlDsaInstance.ML_DSA_65
          && !mlDsa65CompatibleClassicalAlgorithms.contains(classicalAlgorithm)) {
        throw new GeneralSecurityException(
            "ML-DSA-65 is not compatible with the provided classical algorithm "
                + classicalAlgorithm);
      }
      if (mlDsaInstance == MlDsaInstance.ML_DSA_87
          && !mlDsa87CompatibleClassicalAlgorithms.contains(classicalAlgorithm)) {
        throw new GeneralSecurityException(
            "ML-DSA-87 is not compatible with the provided classical algorithm "
                + classicalAlgorithm);
      }
      if (mlDsaInstance != MlDsaInstance.ML_DSA_65 && mlDsaInstance != MlDsaInstance.ML_DSA_87) {
        throw new GeneralSecurityException("Unknown ML-DSA instance: " + mlDsaInstance);
      }
      return new CompositeMlDsaParameters(mlDsaInstance, classicalAlgorithm, variant);
    }
  }

  private CompositeMlDsaParameters(
      MlDsaInstance mlDsaInstance, ClassicalAlgorithm classicalAlgorithm, Variant variant) {
    this.mlDsaInstance = mlDsaInstance;
    this.classicalAlgorithm = classicalAlgorithm;
    this.variant = variant;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The getters. */
  public MlDsaInstance getMlDsaInstance() {
    return mlDsaInstance;
  }

  public Variant getVariant() {
    return variant;
  }

  public ClassicalAlgorithm getClassicalAlgorithm() {
    return classicalAlgorithm;
  }

  /** The necessary overridden methods. */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CompositeMlDsaParameters)) {
      return false;
    }
    CompositeMlDsaParameters other = (CompositeMlDsaParameters) o;
    return other.getMlDsaInstance() == getMlDsaInstance()
        && other.getClassicalAlgorithm() == getClassicalAlgorithm()
        && other.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(CompositeMlDsaParameters.class, mlDsaInstance, classicalAlgorithm, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "Composite ML-DSA Parameters (ML-DSA instance: "
        + mlDsaInstance
        + ", classical algorithm: "
        + classicalAlgorithm
        + ", variant: "
        + variant
        + ")";
  }
}
