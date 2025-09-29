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

import static com.google.crypto.tink.signature.internal.MlDsaConstants.K_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaConstants.RHO_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaConstants.TR_LENGTH;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.PolyRq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.RingZq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.VectorRq;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

final class MlDsaMarshalUtil {

  // Algorithm 16 (SimpleBitPack) for the case of bitlen(b) == 10.
  static void simpleBitPack10(PolyRq w, byte[] z, int offset) throws GeneralSecurityException {
    if (offset + 320 > z.length) {
      throw new GeneralSecurityException("Provided buffer too short");
    }
    // Every 4 coefficients fill up a full number of bytes (five bytes).
    for (int i = 0; i < MlDsaConstants.DEGREE / 4; i++) {
      int a = w.polynomial[4 * i].r;
      int b = w.polynomial[4 * i + 1].r;
      int c = w.polynomial[4 * i + 2].r;
      int d = w.polynomial[4 * i + 3].r;
      // TODO(b/438727469): evaluate the performance of this check. Strictly speaking, it is
      //   necessary here to safeguard the correctness. However, we might remove it in case it is
      //   not performant enough, and rely on other checks and tests for correctness.
      if (a >= 1024 || b >= 1024 || c >= 1024 || d >= 1024) {
        throw new GeneralSecurityException("Polynomial coefficient too large");
      }
      z[offset + 5 * i] = (byte) a;
      z[offset + 5 * i + 1] = (byte) ((a >> 8) | (b << 2));
      z[offset + 5 * i + 2] = (byte) ((b >> 6) | (c << 4));
      z[offset + 5 * i + 3] = (byte) ((c >> 4) | (d << 6));
      z[offset + 5 * i + 4] = (byte) (d >> 2);
    }
  }

  // Algorithm 17 (BitPack) for the case of bitlen(a + b) == 3, and b == 2.
  static void bitPack3(PolyRq w, byte[] z, int offset) throws GeneralSecurityException {
    if (offset + 96 > z.length) {
      throw new GeneralSecurityException("Provided buffer too short");
    }
    RingZq two = new RingZq(2);
    // Every 8 coefficients fill up a full number of bytes (three bytes).
    for (int i = 0; i < MlDsaConstants.DEGREE / 8; i++) {
      int a = two.minus(w.polynomial[8 * i]).r;
      int b = two.minus(w.polynomial[8 * i + 1]).r;
      int c = two.minus(w.polynomial[8 * i + 2]).r;
      int d = two.minus(w.polynomial[8 * i + 3]).r;
      int e = two.minus(w.polynomial[8 * i + 4]).r;
      int f = two.minus(w.polynomial[8 * i + 5]).r;
      int g = two.minus(w.polynomial[8 * i + 6]).r;
      int h = two.minus(w.polynomial[8 * i + 7]).r;
      if (a > 4 || b > 4 || c > 4 || d > 4 || e > 4 || f > 4 || g > 4 || h > 4) {
        throw new GeneralSecurityException("Polynomial coefficients out of bounds");
      }
      z[offset + 3 * i] = (byte) (a | (b << 3) | (c << 6));
      z[offset + 3 * i + 1] = (byte) ((c >> 2) | (d << 1) | (e << 4) | (f << 7));
      z[offset + 3 * i + 2] = (byte) ((f >> 1) | (g << 2) | (h << 5));
    }
  }

  // Algorithm 17 (BitPack) for the case of bitlen(a + b) == 4, and b == 4.
  static void bitPack4(PolyRq w, byte[] z, int offset) throws GeneralSecurityException {
    if (offset + 128 > z.length) {
      throw new GeneralSecurityException("Provided buffer too short");
    }
    RingZq four = new RingZq(4);
    // Every 2 coefficients fill up a full number of bytes (one byte).
    for (int i = 0; i < MlDsaConstants.DEGREE / 2; i++) {
      int a = four.minus(w.polynomial[2 * i]).r;
      int b = four.minus(w.polynomial[2 * i + 1]).r;
      if (a > 8 || b > 8) {
        throw new GeneralSecurityException("Polynomial coefficients out of bounds");
      }
      z[offset + i] = (byte) (a | (b << 4));
    }
  }

  // Algorithm 17 (BitPack) for the case of bitlen(a + b) == 13, and b == 2^12.
  static void bitPack13(PolyRq w, byte[] z, int offset) throws GeneralSecurityException {
    if (offset + 416 > z.length) {
      throw new GeneralSecurityException("Provided buffer too short");
    }
    RingZq twoPowDMinusOne = new RingZq(1 << 12); // 2^(d - 1)
    // Every 8 coefficients fill up a full number of bytes (thirteen bytes).
    for (int i = 0; i < MlDsaConstants.DEGREE / 8; i++) {
      int a = twoPowDMinusOne.minus(w.polynomial[8 * i]).r;
      int b = twoPowDMinusOne.minus(w.polynomial[8 * i + 1]).r;
      int c = twoPowDMinusOne.minus(w.polynomial[8 * i + 2]).r;
      int d = twoPowDMinusOne.minus(w.polynomial[8 * i + 3]).r;
      int e = twoPowDMinusOne.minus(w.polynomial[8 * i + 4]).r;
      int f = twoPowDMinusOne.minus(w.polynomial[8 * i + 5]).r;
      int g = twoPowDMinusOne.minus(w.polynomial[8 * i + 6]).r;
      int h = twoPowDMinusOne.minus(w.polynomial[8 * i + 7]).r;
      if (a >= MlDsaConstants.TWO_POW_D
          || b >= MlDsaConstants.TWO_POW_D
          || c >= MlDsaConstants.TWO_POW_D
          || d >= MlDsaConstants.TWO_POW_D
          || e >= MlDsaConstants.TWO_POW_D
          || f >= MlDsaConstants.TWO_POW_D
          || g >= MlDsaConstants.TWO_POW_D
          || h >= MlDsaConstants.TWO_POW_D) {
        throw new GeneralSecurityException("Polynomial coefficient too large");
      }
      z[offset + 13 * i] = (byte) a;
      z[offset + 13 * i + 1] = (byte) ((a >> 8) | (b << 5));
      z[offset + 13 * i + 2] = (byte) (b >> 3);
      z[offset + 13 * i + 3] = (byte) ((b >> 11) | (c << 2));
      z[offset + 13 * i + 4] = (byte) ((c >> 6) | (d << 7));
      z[offset + 13 * i + 5] = (byte) (d >> 1);
      z[offset + 13 * i + 6] = (byte) ((d >> 9) | (e << 4));
      z[offset + 13 * i + 7] = (byte) (e >> 4);
      z[offset + 13 * i + 8] = (byte) ((e >> 12) | (f << 1));
      z[offset + 13 * i + 9] = (byte) ((f >> 7) | (g << 6));
      z[offset + 13 * i + 10] = (byte) (g >> 2);
      z[offset + 13 * i + 11] = (byte) ((g >> 10) | (h << 3));
      z[offset + 13 * i + 12] = (byte) (h >> 5);
    }
  }

  // Algorithm 22 (pkEncode).
  // Returns 32 + 32 * k * (bitlen(q - 1) - d) bytes of encoded public key.
  static byte[] pkEncode(byte[] rho, VectorRq t1Bold, MlDsaConstants.Params params)
      throws GeneralSecurityException {
    if (rho.length != RHO_LENGTH || t1Bold.vector.length != params.k) {
      throw new GeneralSecurityException("Invalid parameters length for pkEncode");
    }
    byte[] pk = new byte[params.pkLength];
    System.arraycopy(rho, 0, pk, 0, RHO_LENGTH);
    for (int i = 0; i < params.k; i++) {
      simpleBitPack10(
          t1Bold.vector[i], pk, RHO_LENGTH + 32 * i * MlDsaConstants.COMPRESSED_PK_BIT_LENGTH);
    }
    return pk;
  }

  // Algorithm 24 (skEncode)
  static SecretBytes skEncode(
      byte[] rho,
      byte[] capK,
      byte[] tr,
      VectorRq s1Bold,
      VectorRq s2Bold,
      VectorRq t0Bold,
      MlDsaConstants.Params params)
      throws GeneralSecurityException {
    if (rho.length != RHO_LENGTH
        || capK.length != K_LENGTH
        || tr.length != TR_LENGTH
        || s1Bold.vector.length != params.l
        || s2Bold.vector.length != params.k
        || t0Bold.vector.length != params.k) {
      throw new GeneralSecurityException("Invalid parameters length");
    }

    byte[] sk = new byte[params.skLength];
    System.arraycopy(rho, 0, sk, 0, RHO_LENGTH);
    System.arraycopy(capK, 0, sk, RHO_LENGTH, K_LENGTH);
    System.arraycopy(tr, 0, sk, RHO_LENGTH + K_LENGTH, TR_LENGTH);

    int baseOffset = RHO_LENGTH + K_LENGTH + TR_LENGTH;
    if (params.eta == MlDsaConstants.ML_DSA_87_ETA) {
      for (int i = 0; i < params.l; i++) {
        bitPack3(s1Bold.vector[i], sk, baseOffset + 32 * i * params.bitlen2Eta);
      }
      baseOffset += 32 * params.l * params.bitlen2Eta;
      for (int i = 0; i < params.k; i++) {
        bitPack3(s2Bold.vector[i], sk, baseOffset + 32 * i * params.bitlen2Eta);
      }
    } else if (params.eta == MlDsaConstants.ML_DSA_65_ETA) {
      for (int i = 0; i < params.l; i++) {
        bitPack4(s1Bold.vector[i], sk, baseOffset + 32 * i * params.bitlen2Eta);
      }
      baseOffset += 32 * params.l * params.bitlen2Eta;
      for (int i = 0; i < params.k; i++) {
        bitPack4(s2Bold.vector[i], sk, baseOffset + 32 * i * params.bitlen2Eta);
      }
    }

    baseOffset += 32 * params.k * params.bitlen2Eta;
    for (int i = 0; i < params.k; i++) {
      bitPack13(t0Bold.vector[i], sk, baseOffset + 32 * i * MlDsaConstants.D);
    }

    return SecretBytes.copyFrom(sk, InsecureSecretKeyAccess.get());
  }

  private MlDsaMarshalUtil() {}
}
