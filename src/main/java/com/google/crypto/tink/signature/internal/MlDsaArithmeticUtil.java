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

import java.security.GeneralSecurityException;
import java.util.Arrays;

final class MlDsaArithmeticUtil {

  private MlDsaArithmeticUtil() {}

  static final class MatrixTq {
    final RingTq[][] matrix;

    MatrixTq(int k, int l) throws GeneralSecurityException {
      if (!((k == MlDsaConstants.ML_DSA_65_K && l == MlDsaConstants.ML_DSA_65_L) || (k == MlDsaConstants.ML_DSA_87_K && l == MlDsaConstants.ML_DSA_87_L))) {
        throw new GeneralSecurityException("Wrong size of the ML-DSA matrix: k=" + k + ", l=" + l);
      }
      matrix = new RingTq[k][l];
      for (int i = 0; i < k; i++) {
        for (int j = 0; j < l; j++) {
          matrix[i][j] = new RingTq();
        }
      }
    }

    // Algorithm 48 (MatrixVectorNTT)
    VectorTq multiplyVector(VectorTq other) throws GeneralSecurityException {
      if (matrix[0].length != other.vector.length) {
        throw new GeneralSecurityException(
            "Invalid parameters for matrix multiplication: matrix size ("
                + matrix.length
                + ", "
                + matrix[0].length
                + "), vector size "
                + other.vector.length);
      }

      VectorTq result = new VectorTq(matrix.length);
      for (int i = 0; i < matrix.length; i++) {
        for (int j = 0; j < other.vector.length; j++) {
          result.vector[i] = result.vector[i].plus(matrix[i][j].multiply(other.vector[j]));
        }
      }
      return result;
    }
  }

  static final class VectorTq {
    final RingTq[] vector;

    VectorTq(int l) {
      vector = new RingTq[l];
      for (int i = 0; i < l; i++) {
        vector[i] = new RingTq();
      }
    }
  }

  // An element of T_q.
  static final class RingTq {
    final RingZq[] vector;

    RingTq() {
      vector = new RingZq[MlDsaConstants.DEGREE];
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        vector[i] = new RingZq(0);
      }
    }

    static RingTq copyFromPolynomial(PolyRq polynomial) {
      RingTq result = new RingTq();
      System.arraycopy(polynomial.polynomial, 0, result.vector, 0, MlDsaConstants.DEGREE);
      return result;
    }

    // Algorithm 44 (AddNTT)
    RingTq plus(RingTq other) {
      RingTq result = new RingTq();
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        result.vector[i] = vector[i].plus(other.vector[i]);
      }
      return result;
    }

    // Algorithm 45 (MultiplyNTT)
    RingTq multiply(RingTq other) {
      RingTq result = new RingTq();
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        result.vector[i] = vector[i].multiply(other.vector[i]);
      }
      return result;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof RingTq)) {
        return false;
      }
      RingTq other = (RingTq) o;
      return Arrays.equals(vector, other.vector);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(vector);
    }
  }

  static final class VectorRqPair {
    VectorRq s1;
    VectorRq s2;

    VectorRqPair(int l1, int l2) {
      s1 = new VectorRq(l1);
      s2 = new VectorRq(l2);
    }
  }

  static final class VectorRq {
    final PolyRq[] vector;

    VectorRq(int l) {
      vector = new PolyRq[l];
      for (int i = 0; i < l; i++) {
        vector[i] = new PolyRq();
      }
    }
  }

  static final class PolyRqPair {
    final PolyRq t1Bold;
    final PolyRq t0Bold;

    PolyRqPair(PolyRq t1Bold, PolyRq t0Bold) {
      this.t1Bold = t1Bold;
      this.t0Bold = t0Bold;
    }
  }

  // A polynomial in R_q.
  static final class PolyRq {
    final RingZq[] polynomial;

    static PolyRq copyFromVector(RingTq vector) {
      PolyRq result = new PolyRq();
      System.arraycopy(vector.vector, 0, result.polynomial, 0, MlDsaConstants.DEGREE);
      return result;
    }

    PolyRq() {
      polynomial = new RingZq[MlDsaConstants.DEGREE];
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        polynomial[i] = new RingZq(0);
      }
    }

    PolyRq plus(PolyRq other) {
      PolyRq result = new PolyRq();
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        result.polynomial[i] = polynomial[i].plus(other.polynomial[i]);
      }
      return result;
    }

    // Algorithm 35 (Power2Round)
    PolyRqPair power2Round() {
      PolyRq t1Bold = new PolyRq();
      PolyRq t0Bold = new PolyRq();
      RingZqPair result;
      for (int i = 0; i < MlDsaConstants.DEGREE; i++) {
        result = polynomial[i].power2Round();
        t1Bold.polynomial[i] = result.r1;
        t0Bold.polynomial[i] = result.r0;
      }
      return new PolyRqPair(t1Bold, t0Bold);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof PolyRq)) {
        return false;
      }
      PolyRq other = (PolyRq) o;
      return Arrays.equals(polynomial, other.polynomial);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(polynomial);
    }
  }

  static final class RingZqPair {
    final RingZq r1;
    final RingZq r0;

    RingZqPair(int r1, int r0) {
      this.r1 = new RingZq(r1);
      this.r0 = new RingZq(r0);
    }
  }

  // Ring of (23-bit long) integers modulo q = 2^23 - 2^13 + 1 = 8380417.
  static final class RingZq {

    static final RingZq INVALID = new RingZq(-1);
    static final int Q = 8380417;

    final int r;

    RingZq(int r) {
      if ((r < 0 || r >= Q) && INVALID != null) {
        this.r = INVALID.r;
        return;
      }
      this.r = r;
    }

    RingZq plus(RingZq other) {
      return new RingZq((r + other.r) % Q);
    }

    RingZq minus(RingZq other) {
      return new RingZq((r - other.r + Q) % Q);
    }

    RingZq multiply(RingZq other) {
      return new RingZq((int) ((((long) r) * ((long) other.r)) % Q));
    }

    RingZq negative() {
      return new RingZq((Q - r) % Q);
    }

    // Algorithm 35 (Power2Round)
    RingZqPair power2Round() {
      int rPlus = r % Q;
      int rZero =
          (((rPlus + MlDsaConstants.TWO_POW_D_MINUS_ONE - 1) & (MlDsaConstants.TWO_POW_D - 1))
                  - (MlDsaConstants.TWO_POW_D_MINUS_ONE - 1)
                  + Q)
              % Q;
      int rOne = ((rPlus - rZero + Q) % Q) >> MlDsaConstants.D;
      return new RingZqPair(rOne, rZero);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof RingZq)) {
        return false;
      }
      RingZq other = (RingZq) o;
      return r == other.r;
    }

    @Override
    public int hashCode() {
      return Integer.hashCode(r);
    }
  }
}
