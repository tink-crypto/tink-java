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

import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Describes the parameters of a {@code JwtMlDsaPrivateKey} or a {@code JwtMlDsaPublicKey}. */
public final class JwtMlDsaParameters extends JwtSignatureParameters {
  /** Specifies how the "kid" header is handled. */
  @Immutable
  public static final class KidStrategy {
    /**
     * The "kid" is the URL safe (RFC 4648 Section 5) base64-encoded big-endian key_id in the
     * keyset.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink always adds the KID.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode} Tink checks that the kid is present and equal
     * to this value.
     *
     * <p>This strategy is recommended by Tink.
     */
    public static final KidStrategy BASE64_ENCODED_KEY_ID =
        new KidStrategy("BASE64_ENCODED_KEY_ID");

    /**
     * The "kid" header is ignored.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink does not write a "kid" header.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode} Tink ignores the "kid" header.
     */
    public static final KidStrategy IGNORED = new KidStrategy("IGNORED");

    /**
     * The "kid" is fixed. It can be obtained from {@code parameters.getCustomKid()}.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink writes the "kid" header to the value given by
     * {@code parameters.getCustomKid()}.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode}, if the kid is present, it needs to match
     * {@code parameters.getCustomKid()}. If the kid is absent, it will be accepted.
     *
     * <p>Note: Tink does not allow to randomly generate new {@link JwtMlDsaPrivateKey} objects from
     * parameters objects with {@code KidStrategy} equals to {@code CUSTOM}.
     */
    public static final KidStrategy CUSTOM = new KidStrategy("CUSTOM");

    private final String name;

    private KidStrategy(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The algorithm to be used for the signature computation. */
  @Immutable
  public static final class Algorithm {
    public static final Algorithm ML_DSA_44 = new Algorithm("ML-DSA-44");
    public static final Algorithm ML_DSA_65 = new Algorithm("ML-DSA-65");
    public static final Algorithm ML_DSA_87 = new Algorithm("ML-DSA-87");

    private final String name;

    private Algorithm(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }

    public String getStandardName() {
      return name;
    }
  }

  private final KidStrategy kidStrategy;
  private final Algorithm algorithm;

  public static JwtMlDsaParameters create(KidStrategy kidStrategy, Algorithm algorithm) {
    return new JwtMlDsaParameters(kidStrategy, algorithm);
  }

  private JwtMlDsaParameters(KidStrategy kidStrategy, Algorithm algorithm) {
    this.kidStrategy = kidStrategy;
    this.algorithm = algorithm;
  }

  public KidStrategy getKidStrategy() {
    return kidStrategy;
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public boolean hasIdRequirement() {
    return kidStrategy.equals(KidStrategy.BASE64_ENCODED_KEY_ID);
  }

  @Override
  public boolean allowKidAbsent() {
    return kidStrategy.equals(KidStrategy.CUSTOM) || kidStrategy.equals(KidStrategy.IGNORED);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof JwtMlDsaParameters)) {
      return false;
    }
    JwtMlDsaParameters that = (JwtMlDsaParameters) o;
    return that.kidStrategy.equals(kidStrategy) && that.algorithm.equals(algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(JwtMlDsaParameters.class, kidStrategy, algorithm);
  }

  @Override
  public String toString() {
    return "JWT ML-DSA Parameters (kidStrategy: " + kidStrategy + ", Algorithm " + algorithm + ")";
  }
}
