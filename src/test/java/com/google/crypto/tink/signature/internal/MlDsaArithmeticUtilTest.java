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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.MatrixTq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.PolyRq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.RingTq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.RingZq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.VectorTq;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MlDsaArithmeticUtilTest {

  @Test
  public void ringZq_invalid_isInvalid() throws Exception {
    assertThat(RingZq.INVALID.r).isEqualTo(-1);
  }

  @Test
  public void ringZq_plus_works() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    assertThat(a.plus(b).r).isEqualTo(579);
  }

  @Test
  public void ringZq_plus_worksWithOverflow() throws Exception {
    RingZq a = new RingZq(MlDsaArithmeticUtil.RingZq.Q - 123);
    RingZq b = new RingZq(456);
    assertThat(a.plus(b).r).isEqualTo(333);
  }

  @Test
  public void ringZq_plusZero_isNeutral() throws Exception {
    RingZq a = new RingZq(123);
    RingZq zero = new RingZq(0);
    assertThat(a.plus(zero)).isEqualTo(a);
    assertThat(zero.plus(a)).isEqualTo(a);
  }

  @Test
  public void ringZq_plus_isAssociative() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    RingZq c = new RingZq(789);
    assertThat(a.plus(b).plus(c)).isEqualTo(a.plus(b.plus(c)));
  }

  @Test
  public void ringZq_plus_isCommutative() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    assertThat(a.plus(b)).isEqualTo(b.plus(a));
  }

  @Test
  public void ringZq_minus_works() throws Exception {
    RingZq a = new RingZq(456);
    RingZq b = new RingZq(123);
    assertThat(a.minus(b).r).isEqualTo(333);
  }

  @Test
  public void ringZq_minus_worksWithOverflow() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    assertThat(a.minus(b).r).isEqualTo(8380084);
  }

  @Test
  public void ringZq_multiply_works() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    assertThat(a.multiply(b).r).isEqualTo(56088);
  }

  @Test
  public void ringZq_multiply_worksWithOverflow() throws Exception {
    RingZq a = new RingZq(123000);
    RingZq b = new RingZq(456000);
    assertThat(a.multiply(b).r).isEqualTo(6249436);
  }

  @Test
  public void ringZq_multiplyZero_isZero() throws Exception {
    RingZq a = new RingZq(123);
    RingZq zero = new RingZq(0);
    assertThat(a.multiply(zero)).isEqualTo(zero);
    assertThat(zero.multiply(a)).isEqualTo(zero);
  }

  @Test
  public void ringZq_multiply_isAssociative() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    RingZq c = new RingZq(789);
    assertThat(a.multiply(b).multiply(c)).isEqualTo(a.multiply(b.multiply(c)));
  }

  @Test
  public void ringZq_multiply_isCommutative() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    assertThat(a.multiply(b)).isEqualTo(b.multiply(a));
  }

  @Test
  public void ringZq_negative_works() throws Exception {
    RingZq a = new RingZq(123);
    assertThat(a.negative().r).isEqualTo(8380294);
  }

  @Test
  public void ringZq_negativeZero_isZero() throws Exception {
    RingZq zero = new RingZq(0);
    assertThat(zero.negative()).isEqualTo(zero);
  }

  @Test
  public void ringZq_plusMultiply_isDistributive() throws Exception {
    RingZq a = new RingZq(123);
    RingZq b = new RingZq(456);
    RingZq c = new RingZq(789);
    assertThat(a.multiply(b.plus(c)).r).isEqualTo(a.multiply(b).plus(a.multiply(c)).r);
  }

  @Test
  public void ringZq_power2Round_works() throws Exception {
    RingZq a = new RingZq(1234567);
    MlDsaArithmeticUtil.RingZqPair pair = a.power2Round();
    RingZq r1 = pair.r1;
    RingZq r0 = pair.r0;
    assertThat(r1.r).isEqualTo(151);
    assertThat(r0.r).isEqualTo(8377992);
    assertThat(r1.multiply(new RingZq(1 << MlDsaArithmeticUtil.D)).plus(r0)).isEqualTo(a);
  }

  @Test
  public void ringZq_power2Round_equasionHolds() throws Exception {
    for (int i = 0; i < RingZq.Q; i++) {
      RingZq a = new RingZq(i);
      MlDsaArithmeticUtil.RingZqPair pair = a.power2Round();
      RingZq r1 = pair.r1;
      RingZq r0 = pair.r0;
      assertThat(r1.multiply(new RingZq(1 << MlDsaArithmeticUtil.D)).plus(r0)).isEqualTo(a);
    }
  }

  @Test
  public void ringTq_plus_works() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
    }

    RingTq c = a.plus(b);

    for (int i = 0; i < MlDsaArithmeticUtil.DEGREE; i++) {
      assertThat(c.vector[i].r)
          .isEqualTo((1110 * i * i + 1110 * i + 1110) % MlDsaArithmeticUtil.RingZq.Q);
    }
  }

  @Test
  public void ringTq_plusZero_isNeutral() throws Exception {
    RingTq a = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
    }
    RingTq zero = new RingTq();
    assertThat(a.plus(zero)).isEqualTo(a);
    assertThat(zero.plus(a)).isEqualTo(a);
  }

  @Test
  public void ringTq_plus_isAssociative() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    RingTq c = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
      c.vector[i] = new RingZq((111 * i * i + 222 * i + 333) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.plus(b).plus(c)).isEqualTo(a.plus(b.plus(c)));
  }

  @Test
  public void ringTq_plus_isCommutative() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.plus(b)).isEqualTo(b.plus(a));
  }

  @Test
  public void ringTq_multiply_works() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((10 * i + 10) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((100 * i + 100) % MlDsaArithmeticUtil.RingZq.Q);
    }

    RingTq c = a.multiply(b);

    for (int i = 0; i < 256; i++) {
      assertThat(c.vector[i].r)
          .isEqualTo((1000 * i * i + 2000 * i + 1000) % MlDsaArithmeticUtil.RingZq.Q);
    }
  }

  @Test
  public void ringTq_multiplyZero_isZero() throws Exception {
    RingTq a = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
    }
    RingTq zero = new RingTq();
    assertThat(a.multiply(zero)).isEqualTo(zero);
    assertThat(zero.multiply(a)).isEqualTo(zero);
  }

  @Test
  public void ringTq_multiply_isAssociative() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    RingTq c = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((10 * i + 10) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((100 * i + 100) % MlDsaArithmeticUtil.RingZq.Q);
      c.vector[i] = new RingZq((1000 * i + 1000) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.multiply(b).multiply(c)).isEqualTo(a.multiply(b.multiply(c)));
  }

  @Test
  public void ringTq_multiply_isCommutative() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((10 * i + 10) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((100 * i + 100) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.multiply(b)).isEqualTo(b.multiply(a));
  }

  @Test
  public void ringTq_plusMultiply_isDistributive() throws Exception {
    RingTq a = new RingTq();
    RingTq b = new RingTq();
    RingTq c = new RingTq();
    for (int i = 0; i < 256; i++) {
      a.vector[i] = new RingZq((10 * i + 10) % MlDsaArithmeticUtil.RingZq.Q);
      b.vector[i] = new RingZq((100 * i + 100) % MlDsaArithmeticUtil.RingZq.Q);
      c.vector[i] = new RingZq((1000 * i + 1000) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.multiply(b.plus(c))).isEqualTo(a.multiply(b).plus(a.multiply(c)));
  }

  @Test
  public void polyRq_plus_works() throws Exception {
    PolyRq a = new PolyRq();
    PolyRq b = new PolyRq();
    for (int i = 0; i < 256; i++) {
      a.polynomial[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.polynomial[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
    }

    PolyRq c = a.plus(b);

    for (int i = 0; i < MlDsaArithmeticUtil.DEGREE; i++) {
      assertThat(c.polynomial[i].r)
          .isEqualTo((1110 * i * i + 1110 * i + 1110) % MlDsaArithmeticUtil.RingZq.Q);
    }
  }

  @Test
  public void polyRq_plusZero_isNeutral() throws Exception {
    PolyRq a = new PolyRq();
    for (int i = 0; i < 256; i++) {
      a.polynomial[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
    }
    PolyRq zero = new PolyRq();
    assertThat(a.plus(zero)).isEqualTo(a);
    assertThat(zero.plus(a)).isEqualTo(a);
  }

  @Test
  public void polyRq_plus_isAssociative() throws Exception {
    PolyRq a = new PolyRq();
    PolyRq b = new PolyRq();
    PolyRq c = new PolyRq();
    for (int i = 0; i < 256; i++) {
      a.polynomial[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.polynomial[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
      c.polynomial[i] = new RingZq((111 * i * i + 222 * i + 333) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.plus(b).plus(c)).isEqualTo(a.plus(b.plus(c)));
  }

  @Test
  public void polyRq_plus_isCommutative() throws Exception {
    PolyRq a = new PolyRq();
    PolyRq b = new PolyRq();
    for (int i = 0; i < 256; i++) {
      a.polynomial[i] = new RingZq((123 * i * i + 456 * i + 789) % MlDsaArithmeticUtil.RingZq.Q);
      b.polynomial[i] = new RingZq((987 * i * i + 654 * i + 321) % MlDsaArithmeticUtil.RingZq.Q);
    }
    assertThat(a.plus(b)).isEqualTo(b.plus(a));
  }

  @Test
  public void matrixTq_multiplyVector_works() throws Exception {
    MatrixTq matrixTq = new MatrixTq(6, 5);
    VectorTq vectorTq = new VectorTq(5);
    for (int i = 0; i < 6; i++) {
      for (int j = 0; j < 5; j++) {
        for (int l = 0; l < 256; l++) {
          matrixTq.matrix[i][j].vector[l] = new RingZq((i + j + l) % MlDsaArithmeticUtil.RingZq.Q);
        }
      }
    }
    for (int j = 0; j < 5; j++) {
      for (int l = 0; l < 256; l++) {
        vectorTq.vector[j].vector[l] = new RingZq((j + l) % MlDsaArithmeticUtil.RingZq.Q);
      }
    }

    VectorTq result = matrixTq.multiplyVector(vectorTq);

    for (int k = 0; k < 6; k++) {
      for (int l = 0; l < 256; l++) {
        assertThat(result.vector[k].vector[l].r)
            .isEqualTo(
                (5 * k * l + 5 * l * l + 10 * k + 20 * l + 30) % MlDsaArithmeticUtil.RingZq.Q);
      }
    }
  }
}
