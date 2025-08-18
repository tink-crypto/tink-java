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

import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Describes the parameters of ML-DSA signature primitive. */
public final class MlDsaParameters extends SignatureParameters {
  /**
   * Describes details of the ML-DSA signature format.
   *
   * <p>The standard ML-DSA key is used for variant "NO_PREFIX". "TINK" adds a prefix to every
   * computation depending on the key id.
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
   * In the beginning, only ML-DSA-65 will be supported on the implementation side, but we still
   * add ML-DSA-87 since the implementation is going to be added in the near future.
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

  private final MlDsaInstance mlDsaInstance;
  private final Variant variant;

  /** Create an instance with a given parameters set and variant. */
  public static MlDsaParameters create(MlDsaInstance mlDsaInstance, Variant variant) {
    return new MlDsaParameters(mlDsaInstance, variant);
  }

  private MlDsaParameters(MlDsaInstance mlDsaInstance, Variant variant) {
    this.mlDsaInstance = mlDsaInstance;
    this.variant = variant;
  }

  public MlDsaInstance getMlDsaInstance() {
    return mlDsaInstance;
  }

  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof MlDsaParameters)) {
      return false;
    }
    MlDsaParameters other = (MlDsaParameters) o;
    return other.getMlDsaInstance() == getMlDsaInstance() && other.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(MlDsaParameters.class, mlDsaInstance, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "ML-DSA Parameters (ML-DSA instance: " + mlDsaInstance + ", variant: " + variant + ")";
  }
}
