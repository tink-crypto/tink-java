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

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class JwtMlDsaParametersTest {

  private static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final boolean expectedHasIdRequirement;
    final boolean expectedAllowKidAbsent;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        boolean expectedHasIdRequirement,
        boolean expectedAllowKidAbsent) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.expectedHasIdRequirement = expectedHasIdRequirement;
      this.expectedAllowKidAbsent = expectedAllowKidAbsent;
    }
  }

  @DataPoints("ml_dsa_parameters")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* expectedHasIdRequirement= */ true,
        /* expectedAllowKidAbsent= */ false),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* expectedHasIdRequirement= */ false,
        /* expectedAllowKidAbsent= */ true),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* expectedHasIdRequirement= */ false,
        /* expectedAllowKidAbsent= */ true)
  };

  @Theory
  public void createParameters(@FromDataPoints("ml_dsa_parameters") TestVector testVector) {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);

    assertThat(parameters.getKidStrategy()).isEqualTo(testVector.kidStrategy);
    assertThat(parameters.getAlgorithm()).isEqualTo(testVector.algorithm);
    assertThat(parameters.hasIdRequirement()).isEqualTo(testVector.expectedHasIdRequirement);
    assertThat(parameters.allowKidAbsent()).isEqualTo(testVector.expectedAllowKidAbsent);
  }

  @Test
  public void equalsAndHashCode_identical_isEqual() throws Exception {
    JwtMlDsaParameters parameters1 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters parameters2 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    assertThat(parameters1).isEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
  }

  @Test
  public void equalsAndHashCode_differentAlgorithm_isNotEqual() throws Exception {
    JwtMlDsaParameters parameters1 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters parameters2 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }

  @Test
  public void equalsAndHashCode_differentKidStrategy_isNotEqual() throws Exception {
    JwtMlDsaParameters parameters1 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaParameters parameters2 =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    assertThat(parameters1).isNotEqualTo(parameters2);
    assertThat(parameters1.hashCode()).isNotEqualTo(parameters2.hashCode());
  }
}
