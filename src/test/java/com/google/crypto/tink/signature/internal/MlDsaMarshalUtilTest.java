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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.PolyRq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.RingZq;
import com.google.crypto.tink.signature.internal.MlDsaArithmeticUtil.VectorRq;
import com.google.crypto.tink.util.SecretBytes;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MlDsaMarshalUtilTest {

  // `bitPack`/`simpleBitPack` test vectors taken from
  // experimental/users/guillaumee/pqrs/src/bits.rs.

  private static final MlDsaConstants.Params ML_DSA_65_PARAMS =
      new MlDsaConstants.Params(
          (byte) MlDsaConstants.ML_DSA_65_K,
          (byte) MlDsaConstants.ML_DSA_65_L,
          4,
          32 + 32 * MlDsaConstants.ML_DSA_65_K * (23 - MlDsaConstants.D),
          4,
          32
              + 32
              + 64
              + 32
                  * ((MlDsaConstants.ML_DSA_65_K + MlDsaConstants.ML_DSA_65_L) * 4
                      + MlDsaConstants.D * MlDsaConstants.ML_DSA_65_K),
          MlDsaInstance.ML_DSA_65);

  @Test
  public void simpleBitPack10_smokeTest() throws Exception {
    PolyRq w = new PolyRq(); // All zeros
    byte[] packed = new byte[320];

    MlDsaMarshalUtil.simpleBitPack10(w, packed, 0);

    assertThat(packed).isEqualTo(new byte[320]);
  }

  @Test
  public void simpleBitPack10_works() throws Exception {
    // Test vector from experimental/users/guillaumee/pqrs/src/bits.rs:test_simple_bit_pack_10
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(i);
    }
    byte[] packed = new byte[320];

    MlDsaMarshalUtil.simpleBitPack10(w, packed, 0);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 4, (byte) 32, (byte) 192, (byte) 0, (byte) 4, (byte) 20, (byte) 96,
              (byte) 192, (byte) 1, (byte) 8, (byte) 36, (byte) 160, (byte) 192, (byte) 2,
              (byte) 12, (byte) 52, (byte) 224, (byte) 192, (byte) 3, (byte) 16, (byte) 68,
              (byte) 32, (byte) 193, (byte) 4, (byte) 20, (byte) 84, (byte) 96, (byte) 193,
              (byte) 5, (byte) 24, (byte) 100, (byte) 160, (byte) 193, (byte) 6, (byte) 28,
              (byte) 116, (byte) 224, (byte) 193, (byte) 7, (byte) 32, (byte) 132, (byte) 32,
              (byte) 194, (byte) 8, (byte) 36, (byte) 148, (byte) 96, (byte) 194, (byte) 9,
              (byte) 40, (byte) 164, (byte) 160, (byte) 194, (byte) 10, (byte) 44, (byte) 180,
              (byte) 224, (byte) 194, (byte) 11, (byte) 48, (byte) 196, (byte) 32, (byte) 195,
              (byte) 12, (byte) 52, (byte) 212, (byte) 96, (byte) 195, (byte) 13, (byte) 56,
              (byte) 228, (byte) 160, (byte) 195, (byte) 14, (byte) 60, (byte) 244, (byte) 224,
              (byte) 195, (byte) 15, (byte) 64, (byte) 4, (byte) 33, (byte) 196, (byte) 16,
              (byte) 68, (byte) 20, (byte) 97, (byte) 196, (byte) 17, (byte) 72, (byte) 36,
              (byte) 161, (byte) 196, (byte) 18, (byte) 76, (byte) 52, (byte) 225, (byte) 196,
              (byte) 19, (byte) 80, (byte) 68, (byte) 33, (byte) 197, (byte) 20, (byte) 84,
              (byte) 84, (byte) 97, (byte) 197, (byte) 21, (byte) 88, (byte) 100, (byte) 161,
              (byte) 197, (byte) 22, (byte) 92, (byte) 116, (byte) 225, (byte) 197, (byte) 23,
              (byte) 96, (byte) 132, (byte) 33, (byte) 198, (byte) 24, (byte) 100, (byte) 148,
              (byte) 97, (byte) 198, (byte) 25, (byte) 104, (byte) 164, (byte) 161, (byte) 198,
              (byte) 26, (byte) 108, (byte) 180, (byte) 225, (byte) 198, (byte) 27, (byte) 112,
              (byte) 196, (byte) 33, (byte) 199, (byte) 28, (byte) 116, (byte) 212, (byte) 97,
              (byte) 199, (byte) 29, (byte) 120, (byte) 228, (byte) 161, (byte) 199, (byte) 30,
              (byte) 124, (byte) 244, (byte) 225, (byte) 199, (byte) 31, (byte) 128, (byte) 4,
              (byte) 34, (byte) 200, (byte) 32, (byte) 132, (byte) 20, (byte) 98, (byte) 200,
              (byte) 33, (byte) 136, (byte) 36, (byte) 162, (byte) 200, (byte) 34, (byte) 140,
              (byte) 52, (byte) 226, (byte) 200, (byte) 35, (byte) 144, (byte) 68, (byte) 34,
              (byte) 201, (byte) 36, (byte) 148, (byte) 84, (byte) 98, (byte) 201, (byte) 37,
              (byte) 152, (byte) 100, (byte) 162, (byte) 201, (byte) 38, (byte) 156, (byte) 116,
              (byte) 226, (byte) 201, (byte) 39, (byte) 160, (byte) 132, (byte) 34, (byte) 202,
              (byte) 40, (byte) 164, (byte) 148, (byte) 98, (byte) 202, (byte) 41, (byte) 168,
              (byte) 164, (byte) 162, (byte) 202, (byte) 42, (byte) 172, (byte) 180, (byte) 226,
              (byte) 202, (byte) 43, (byte) 176, (byte) 196, (byte) 34, (byte) 203, (byte) 44,
              (byte) 180, (byte) 212, (byte) 98, (byte) 203, (byte) 45, (byte) 184, (byte) 228,
              (byte) 162, (byte) 203, (byte) 46, (byte) 188, (byte) 244, (byte) 226, (byte) 203,
              (byte) 47, (byte) 192, (byte) 4, (byte) 35, (byte) 204, (byte) 48, (byte) 196,
              (byte) 20, (byte) 99, (byte) 204, (byte) 49, (byte) 200, (byte) 36, (byte) 163,
              (byte) 204, (byte) 50, (byte) 204, (byte) 52, (byte) 227, (byte) 204, (byte) 51,
              (byte) 208, (byte) 68, (byte) 35, (byte) 205, (byte) 52, (byte) 212, (byte) 84,
              (byte) 99, (byte) 205, (byte) 53, (byte) 216, (byte) 100, (byte) 163, (byte) 205,
              (byte) 54, (byte) 220, (byte) 116, (byte) 227, (byte) 205, (byte) 55, (byte) 224,
              (byte) 132, (byte) 35, (byte) 206, (byte) 56, (byte) 228, (byte) 148, (byte) 99,
              (byte) 206, (byte) 57, (byte) 232, (byte) 164, (byte) 163, (byte) 206, (byte) 58,
              (byte) 236, (byte) 180, (byte) 227, (byte) 206, (byte) 59, (byte) 240, (byte) 196,
              (byte) 35, (byte) 207, (byte) 60, (byte) 244, (byte) 212, (byte) 99, (byte) 207,
              (byte) 61, (byte) 248, (byte) 228, (byte) 163, (byte) 207, (byte) 62, (byte) 252,
              (byte) 244, (byte) 227, (byte) 207, (byte) 63
            });
  }

  @Test
  public void simpleBitPack10_worksWithOffset() throws Exception {
    // Test vector from experimental/users/guillaumee/pqrs/src/bits.rs:test_simple_bit_pack_10
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(i);
    }
    byte[] packed = new byte[1 + 320 + 1];

    MlDsaMarshalUtil.simpleBitPack10(w, packed, 1);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 0, (byte) 4, (byte) 32, (byte) 192, (byte) 0, (byte) 4, (byte) 20,
              (byte) 96, (byte) 192, (byte) 1, (byte) 8, (byte) 36, (byte) 160, (byte) 192,
              (byte) 2, (byte) 12, (byte) 52, (byte) 224, (byte) 192, (byte) 3, (byte) 16,
              (byte) 68, (byte) 32, (byte) 193, (byte) 4, (byte) 20, (byte) 84, (byte) 96,
              (byte) 193, (byte) 5, (byte) 24, (byte) 100, (byte) 160, (byte) 193, (byte) 6,
              (byte) 28, (byte) 116, (byte) 224, (byte) 193, (byte) 7, (byte) 32, (byte) 132,
              (byte) 32, (byte) 194, (byte) 8, (byte) 36, (byte) 148, (byte) 96, (byte) 194,
              (byte) 9, (byte) 40, (byte) 164, (byte) 160, (byte) 194, (byte) 10, (byte) 44,
              (byte) 180, (byte) 224, (byte) 194, (byte) 11, (byte) 48, (byte) 196, (byte) 32,
              (byte) 195, (byte) 12, (byte) 52, (byte) 212, (byte) 96, (byte) 195, (byte) 13,
              (byte) 56, (byte) 228, (byte) 160, (byte) 195, (byte) 14, (byte) 60, (byte) 244,
              (byte) 224, (byte) 195, (byte) 15, (byte) 64, (byte) 4, (byte) 33, (byte) 196,
              (byte) 16, (byte) 68, (byte) 20, (byte) 97, (byte) 196, (byte) 17, (byte) 72,
              (byte) 36, (byte) 161, (byte) 196, (byte) 18, (byte) 76, (byte) 52, (byte) 225,
              (byte) 196, (byte) 19, (byte) 80, (byte) 68, (byte) 33, (byte) 197, (byte) 20,
              (byte) 84, (byte) 84, (byte) 97, (byte) 197, (byte) 21, (byte) 88, (byte) 100,
              (byte) 161, (byte) 197, (byte) 22, (byte) 92, (byte) 116, (byte) 225, (byte) 197,
              (byte) 23, (byte) 96, (byte) 132, (byte) 33, (byte) 198, (byte) 24, (byte) 100,
              (byte) 148, (byte) 97, (byte) 198, (byte) 25, (byte) 104, (byte) 164, (byte) 161,
              (byte) 198, (byte) 26, (byte) 108, (byte) 180, (byte) 225, (byte) 198, (byte) 27,
              (byte) 112, (byte) 196, (byte) 33, (byte) 199, (byte) 28, (byte) 116, (byte) 212,
              (byte) 97, (byte) 199, (byte) 29, (byte) 120, (byte) 228, (byte) 161, (byte) 199,
              (byte) 30, (byte) 124, (byte) 244, (byte) 225, (byte) 199, (byte) 31, (byte) 128,
              (byte) 4, (byte) 34, (byte) 200, (byte) 32, (byte) 132, (byte) 20, (byte) 98,
              (byte) 200, (byte) 33, (byte) 136, (byte) 36, (byte) 162, (byte) 200, (byte) 34,
              (byte) 140, (byte) 52, (byte) 226, (byte) 200, (byte) 35, (byte) 144, (byte) 68,
              (byte) 34, (byte) 201, (byte) 36, (byte) 148, (byte) 84, (byte) 98, (byte) 201,
              (byte) 37, (byte) 152, (byte) 100, (byte) 162, (byte) 201, (byte) 38, (byte) 156,
              (byte) 116, (byte) 226, (byte) 201, (byte) 39, (byte) 160, (byte) 132, (byte) 34,
              (byte) 202, (byte) 40, (byte) 164, (byte) 148, (byte) 98, (byte) 202, (byte) 41,
              (byte) 168, (byte) 164, (byte) 162, (byte) 202, (byte) 42, (byte) 172, (byte) 180,
              (byte) 226, (byte) 202, (byte) 43, (byte) 176, (byte) 196, (byte) 34, (byte) 203,
              (byte) 44, (byte) 180, (byte) 212, (byte) 98, (byte) 203, (byte) 45, (byte) 184,
              (byte) 228, (byte) 162, (byte) 203, (byte) 46, (byte) 188, (byte) 244, (byte) 226,
              (byte) 203, (byte) 47, (byte) 192, (byte) 4, (byte) 35, (byte) 204, (byte) 48,
              (byte) 196, (byte) 20, (byte) 99, (byte) 204, (byte) 49, (byte) 200, (byte) 36,
              (byte) 163, (byte) 204, (byte) 50, (byte) 204, (byte) 52, (byte) 227, (byte) 204,
              (byte) 51, (byte) 208, (byte) 68, (byte) 35, (byte) 205, (byte) 52, (byte) 212,
              (byte) 84, (byte) 99, (byte) 205, (byte) 53, (byte) 216, (byte) 100, (byte) 163,
              (byte) 205, (byte) 54, (byte) 220, (byte) 116, (byte) 227, (byte) 205, (byte) 55,
              (byte) 224, (byte) 132, (byte) 35, (byte) 206, (byte) 56, (byte) 228, (byte) 148,
              (byte) 99, (byte) 206, (byte) 57, (byte) 232, (byte) 164, (byte) 163, (byte) 206,
              (byte) 58, (byte) 236, (byte) 180, (byte) 227, (byte) 206, (byte) 59, (byte) 240,
              (byte) 196, (byte) 35, (byte) 207, (byte) 60, (byte) 244, (byte) 212, (byte) 99,
              (byte) 207, (byte) 61, (byte) 248, (byte) 228, (byte) 163, (byte) 207, (byte) 62,
              (byte) 252, (byte) 244, (byte) 227, (byte) 207, (byte) 63, (byte) 0
            });
  }

  @Test
  public void bitPack3_works() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(((i % 5) - 2 + RingZq.Q) % RingZq.Q);
    }
    byte[] packed = new byte[96];

    MlDsaMarshalUtil.bitPack3(w, packed, 0);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128, (byte) 83,
              (byte) 192, (byte) 41, (byte) 224, (byte) 20, (byte) 112, (byte) 10, (byte) 56,
              (byte) 5, (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128,
              (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20, (byte) 112, (byte) 10,
              (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167,
              (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20, (byte) 112,
              (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78, (byte) 1,
              (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20,
              (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78,
              (byte) 1, (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224,
              (byte) 20, (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2,
              (byte) 78, (byte) 1, (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41,
              (byte) 224, (byte) 20, (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156,
              (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128
            });
  }

  @Test
  public void bitPack3_worksWithOffset() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(((i % 5) - 2 + RingZq.Q) % RingZq.Q);
    }
    byte[] packed = new byte[1 + 96 + 1];

    MlDsaMarshalUtil.bitPack3(w, packed, 1);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128,
              (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20, (byte) 112, (byte) 10,
              (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167,
              (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20, (byte) 112,
              (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78, (byte) 1,
              (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224, (byte) 20,
              (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2, (byte) 78,
              (byte) 1, (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41, (byte) 224,
              (byte) 20, (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156, (byte) 2,
              (byte) 78, (byte) 1, (byte) 167, (byte) 128, (byte) 83, (byte) 192, (byte) 41,
              (byte) 224, (byte) 20, (byte) 112, (byte) 10, (byte) 56, (byte) 5, (byte) 156,
              (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128, (byte) 83, (byte) 192,
              (byte) 41, (byte) 224, (byte) 20, (byte) 112, (byte) 10, (byte) 56, (byte) 5,
              (byte) 156, (byte) 2, (byte) 78, (byte) 1, (byte) 167, (byte) 128, (byte) 0
            });
  }

  @Test
  public void bitPack4_works() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(((i % 9) - 4 + RingZq.Q) % RingZq.Q);
    }
    byte[] packed = new byte[128];

    MlDsaMarshalUtil.bitPack4(w, packed, 0);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69,
              (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128,
              (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52,
              (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120,
              (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35,
              (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103,
              (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18,
              (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86,
              (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1,
              (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69,
              (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128,
              (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52,
              (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120,
              (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35,
              (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103,
              (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18,
              (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86,
              (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1,
              (byte) 120, (byte) 86
            });
  }

  @Test
  public void bitPack4_worksWithOffset() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(((i % 9) - 4 + RingZq.Q) % RingZq.Q);
    }
    byte[] packed = new byte[1 + 128 + 1];

    MlDsaMarshalUtil.bitPack4(w, packed, 1);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103,
              (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18,
              (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86,
              (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1,
              (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69,
              (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128,
              (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52,
              (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120,
              (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35,
              (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103,
              (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18,
              (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86,
              (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1,
              (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69,
              (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52, (byte) 18, (byte) 128,
              (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120, (byte) 86, (byte) 52,
              (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35, (byte) 1, (byte) 120,
              (byte) 86, (byte) 52, (byte) 18, (byte) 128, (byte) 103, (byte) 69, (byte) 35,
              (byte) 1, (byte) 120, (byte) 86, (byte) 0
            });
  }

  @Test
  public void bitPack13_works() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(i);
    }
    byte[] packed = new byte[416];

    MlDsaMarshalUtil.bitPack13(w, packed, 0);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 240, (byte) 255, (byte) 249, (byte) 191, (byte) 254, (byte) 199,
              (byte) 255, (byte) 246, (byte) 159, (byte) 254, (byte) 203, (byte) 127, (byte) 248,
              (byte) 239, (byte) 254, (byte) 217, (byte) 191, (byte) 250, (byte) 71, (byte) 255,
              (byte) 230, (byte) 159, (byte) 252, (byte) 139, (byte) 127, (byte) 240, (byte) 239,
              (byte) 253, (byte) 185, (byte) 191, (byte) 246, (byte) 199, (byte) 254, (byte) 214,
              (byte) 159, (byte) 250, (byte) 75, (byte) 127, (byte) 232, (byte) 239, (byte) 252,
              (byte) 153, (byte) 191, (byte) 242, (byte) 71, (byte) 254, (byte) 198, (byte) 159,
              (byte) 248, (byte) 11, (byte) 127, (byte) 224, (byte) 239, (byte) 251, (byte) 121,
              (byte) 191, (byte) 238, (byte) 199, (byte) 253, (byte) 182, (byte) 159, (byte) 246,
              (byte) 203, (byte) 126, (byte) 216, (byte) 239, (byte) 250, (byte) 89, (byte) 191,
              (byte) 234, (byte) 71, (byte) 253, (byte) 166, (byte) 159, (byte) 244, (byte) 139,
              (byte) 126, (byte) 208, (byte) 239, (byte) 249, (byte) 57, (byte) 191, (byte) 230,
              (byte) 199, (byte) 252, (byte) 150, (byte) 159, (byte) 242, (byte) 75, (byte) 126,
              (byte) 200, (byte) 239, (byte) 248, (byte) 25, (byte) 191, (byte) 226, (byte) 71,
              (byte) 252, (byte) 134, (byte) 159, (byte) 240, (byte) 11, (byte) 126, (byte) 192,
              (byte) 239, (byte) 247, (byte) 249, (byte) 190, (byte) 222, (byte) 199, (byte) 251,
              (byte) 118, (byte) 159, (byte) 238, (byte) 203, (byte) 125, (byte) 184, (byte) 239,
              (byte) 246, (byte) 217, (byte) 190, (byte) 218, (byte) 71, (byte) 251, (byte) 102,
              (byte) 159, (byte) 236, (byte) 139, (byte) 125, (byte) 176, (byte) 239, (byte) 245,
              (byte) 185, (byte) 190, (byte) 214, (byte) 199, (byte) 250, (byte) 86, (byte) 159,
              (byte) 234, (byte) 75, (byte) 125, (byte) 168, (byte) 239, (byte) 244, (byte) 153,
              (byte) 190, (byte) 210, (byte) 71, (byte) 250, (byte) 70, (byte) 159, (byte) 232,
              (byte) 11, (byte) 125, (byte) 160, (byte) 239, (byte) 243, (byte) 121, (byte) 190,
              (byte) 206, (byte) 199, (byte) 249, (byte) 54, (byte) 159, (byte) 230, (byte) 203,
              (byte) 124, (byte) 152, (byte) 239, (byte) 242, (byte) 89, (byte) 190, (byte) 202,
              (byte) 71, (byte) 249, (byte) 38, (byte) 159, (byte) 228, (byte) 139, (byte) 124,
              (byte) 144, (byte) 239, (byte) 241, (byte) 57, (byte) 190, (byte) 198, (byte) 199,
              (byte) 248, (byte) 22, (byte) 159, (byte) 226, (byte) 75, (byte) 124, (byte) 136,
              (byte) 239, (byte) 240, (byte) 25, (byte) 190, (byte) 194, (byte) 71, (byte) 248,
              (byte) 6, (byte) 159, (byte) 224, (byte) 11, (byte) 124, (byte) 128, (byte) 239,
              (byte) 239, (byte) 249, (byte) 189, (byte) 190, (byte) 199, (byte) 247, (byte) 246,
              (byte) 158, (byte) 222, (byte) 203, (byte) 123, (byte) 120, (byte) 239, (byte) 238,
              (byte) 217, (byte) 189, (byte) 186, (byte) 71, (byte) 247, (byte) 230, (byte) 158,
              (byte) 220, (byte) 139, (byte) 123, (byte) 112, (byte) 239, (byte) 237, (byte) 185,
              (byte) 189, (byte) 182, (byte) 199, (byte) 246, (byte) 214, (byte) 158, (byte) 218,
              (byte) 75, (byte) 123, (byte) 104, (byte) 239, (byte) 236, (byte) 153, (byte) 189,
              (byte) 178, (byte) 71, (byte) 246, (byte) 198, (byte) 158, (byte) 216, (byte) 11,
              (byte) 123, (byte) 96, (byte) 239, (byte) 235, (byte) 121, (byte) 189, (byte) 174,
              (byte) 199, (byte) 245, (byte) 182, (byte) 158, (byte) 214, (byte) 203, (byte) 122,
              (byte) 88, (byte) 239, (byte) 234, (byte) 89, (byte) 189, (byte) 170, (byte) 71,
              (byte) 245, (byte) 166, (byte) 158, (byte) 212, (byte) 139, (byte) 122, (byte) 80,
              (byte) 239, (byte) 233, (byte) 57, (byte) 189, (byte) 166, (byte) 199, (byte) 244,
              (byte) 150, (byte) 158, (byte) 210, (byte) 75, (byte) 122, (byte) 72, (byte) 239,
              (byte) 232, (byte) 25, (byte) 189, (byte) 162, (byte) 71, (byte) 244, (byte) 134,
              (byte) 158, (byte) 208, (byte) 11, (byte) 122, (byte) 64, (byte) 239, (byte) 231,
              (byte) 249, (byte) 188, (byte) 158, (byte) 199, (byte) 243, (byte) 118, (byte) 158,
              (byte) 206, (byte) 203, (byte) 121, (byte) 56, (byte) 239, (byte) 230, (byte) 217,
              (byte) 188, (byte) 154, (byte) 71, (byte) 243, (byte) 102, (byte) 158, (byte) 204,
              (byte) 139, (byte) 121, (byte) 48, (byte) 239, (byte) 229, (byte) 185, (byte) 188,
              (byte) 150, (byte) 199, (byte) 242, (byte) 86, (byte) 158, (byte) 202, (byte) 75,
              (byte) 121, (byte) 40, (byte) 239, (byte) 228, (byte) 153, (byte) 188, (byte) 146,
              (byte) 71, (byte) 242, (byte) 70, (byte) 158, (byte) 200, (byte) 11, (byte) 121,
              (byte) 32, (byte) 239, (byte) 227, (byte) 121, (byte) 188, (byte) 142, (byte) 199,
              (byte) 241, (byte) 54, (byte) 158, (byte) 198, (byte) 203, (byte) 120, (byte) 24,
              (byte) 239, (byte) 226, (byte) 89, (byte) 188, (byte) 138, (byte) 71, (byte) 241,
              (byte) 38, (byte) 158, (byte) 196, (byte) 139, (byte) 120, (byte) 16, (byte) 239,
              (byte) 225, (byte) 57, (byte) 188, (byte) 134, (byte) 199, (byte) 240, (byte) 22,
              (byte) 158, (byte) 194, (byte) 75, (byte) 120, (byte) 8, (byte) 239, (byte) 224,
              (byte) 25, (byte) 188, (byte) 130, (byte) 71, (byte) 240, (byte) 6, (byte) 158,
              (byte) 192, (byte) 11, (byte) 120
            });
  }

  @Test
  public void bitPack13_worksWithOffset() throws Exception {
    PolyRq w = new PolyRq();
    for (int i = 0; i < 256; i++) {
      w.polynomial[i] = new RingZq(i);
    }
    byte[] packed = new byte[1 + 416 + 1];

    MlDsaMarshalUtil.bitPack13(w, packed, 1);

    assertThat(packed)
        .isEqualTo(
            new byte[] {
              (byte) 0, (byte) 0, (byte) 240, (byte) 255, (byte) 249, (byte) 191, (byte) 254,
              (byte) 199, (byte) 255, (byte) 246, (byte) 159, (byte) 254, (byte) 203, (byte) 127,
              (byte) 248, (byte) 239, (byte) 254, (byte) 217, (byte) 191, (byte) 250, (byte) 71,
              (byte) 255, (byte) 230, (byte) 159, (byte) 252, (byte) 139, (byte) 127, (byte) 240,
              (byte) 239, (byte) 253, (byte) 185, (byte) 191, (byte) 246, (byte) 199, (byte) 254,
              (byte) 214, (byte) 159, (byte) 250, (byte) 75, (byte) 127, (byte) 232, (byte) 239,
              (byte) 252, (byte) 153, (byte) 191, (byte) 242, (byte) 71, (byte) 254, (byte) 198,
              (byte) 159, (byte) 248, (byte) 11, (byte) 127, (byte) 224, (byte) 239, (byte) 251,
              (byte) 121, (byte) 191, (byte) 238, (byte) 199, (byte) 253, (byte) 182, (byte) 159,
              (byte) 246, (byte) 203, (byte) 126, (byte) 216, (byte) 239, (byte) 250, (byte) 89,
              (byte) 191, (byte) 234, (byte) 71, (byte) 253, (byte) 166, (byte) 159, (byte) 244,
              (byte) 139, (byte) 126, (byte) 208, (byte) 239, (byte) 249, (byte) 57, (byte) 191,
              (byte) 230, (byte) 199, (byte) 252, (byte) 150, (byte) 159, (byte) 242, (byte) 75,
              (byte) 126, (byte) 200, (byte) 239, (byte) 248, (byte) 25, (byte) 191, (byte) 226,
              (byte) 71, (byte) 252, (byte) 134, (byte) 159, (byte) 240, (byte) 11, (byte) 126,
              (byte) 192, (byte) 239, (byte) 247, (byte) 249, (byte) 190, (byte) 222, (byte) 199,
              (byte) 251, (byte) 118, (byte) 159, (byte) 238, (byte) 203, (byte) 125, (byte) 184,
              (byte) 239, (byte) 246, (byte) 217, (byte) 190, (byte) 218, (byte) 71, (byte) 251,
              (byte) 102, (byte) 159, (byte) 236, (byte) 139, (byte) 125, (byte) 176, (byte) 239,
              (byte) 245, (byte) 185, (byte) 190, (byte) 214, (byte) 199, (byte) 250, (byte) 86,
              (byte) 159, (byte) 234, (byte) 75, (byte) 125, (byte) 168, (byte) 239, (byte) 244,
              (byte) 153, (byte) 190, (byte) 210, (byte) 71, (byte) 250, (byte) 70, (byte) 159,
              (byte) 232, (byte) 11, (byte) 125, (byte) 160, (byte) 239, (byte) 243, (byte) 121,
              (byte) 190, (byte) 206, (byte) 199, (byte) 249, (byte) 54, (byte) 159, (byte) 230,
              (byte) 203, (byte) 124, (byte) 152, (byte) 239, (byte) 242, (byte) 89, (byte) 190,
              (byte) 202, (byte) 71, (byte) 249, (byte) 38, (byte) 159, (byte) 228, (byte) 139,
              (byte) 124, (byte) 144, (byte) 239, (byte) 241, (byte) 57, (byte) 190, (byte) 198,
              (byte) 199, (byte) 248, (byte) 22, (byte) 159, (byte) 226, (byte) 75, (byte) 124,
              (byte) 136, (byte) 239, (byte) 240, (byte) 25, (byte) 190, (byte) 194, (byte) 71,
              (byte) 248, (byte) 6, (byte) 159, (byte) 224, (byte) 11, (byte) 124, (byte) 128,
              (byte) 239, (byte) 239, (byte) 249, (byte) 189, (byte) 190, (byte) 199, (byte) 247,
              (byte) 246, (byte) 158, (byte) 222, (byte) 203, (byte) 123, (byte) 120, (byte) 239,
              (byte) 238, (byte) 217, (byte) 189, (byte) 186, (byte) 71, (byte) 247, (byte) 230,
              (byte) 158, (byte) 220, (byte) 139, (byte) 123, (byte) 112, (byte) 239, (byte) 237,
              (byte) 185, (byte) 189, (byte) 182, (byte) 199, (byte) 246, (byte) 214, (byte) 158,
              (byte) 218, (byte) 75, (byte) 123, (byte) 104, (byte) 239, (byte) 236, (byte) 153,
              (byte) 189, (byte) 178, (byte) 71, (byte) 246, (byte) 198, (byte) 158, (byte) 216,
              (byte) 11, (byte) 123, (byte) 96, (byte) 239, (byte) 235, (byte) 121, (byte) 189,
              (byte) 174, (byte) 199, (byte) 245, (byte) 182, (byte) 158, (byte) 214, (byte) 203,
              (byte) 122, (byte) 88, (byte) 239, (byte) 234, (byte) 89, (byte) 189, (byte) 170,
              (byte) 71, (byte) 245, (byte) 166, (byte) 158, (byte) 212, (byte) 139, (byte) 122,
              (byte) 80, (byte) 239, (byte) 233, (byte) 57, (byte) 189, (byte) 166, (byte) 199,
              (byte) 244, (byte) 150, (byte) 158, (byte) 210, (byte) 75, (byte) 122, (byte) 72,
              (byte) 239, (byte) 232, (byte) 25, (byte) 189, (byte) 162, (byte) 71, (byte) 244,
              (byte) 134, (byte) 158, (byte) 208, (byte) 11, (byte) 122, (byte) 64, (byte) 239,
              (byte) 231, (byte) 249, (byte) 188, (byte) 158, (byte) 199, (byte) 243, (byte) 118,
              (byte) 158, (byte) 206, (byte) 203, (byte) 121, (byte) 56, (byte) 239, (byte) 230,
              (byte) 217, (byte) 188, (byte) 154, (byte) 71, (byte) 243, (byte) 102, (byte) 158,
              (byte) 204, (byte) 139, (byte) 121, (byte) 48, (byte) 239, (byte) 229, (byte) 185,
              (byte) 188, (byte) 150, (byte) 199, (byte) 242, (byte) 86, (byte) 158, (byte) 202,
              (byte) 75, (byte) 121, (byte) 40, (byte) 239, (byte) 228, (byte) 153, (byte) 188,
              (byte) 146, (byte) 71, (byte) 242, (byte) 70, (byte) 158, (byte) 200, (byte) 11,
              (byte) 121, (byte) 32, (byte) 239, (byte) 227, (byte) 121, (byte) 188, (byte) 142,
              (byte) 199, (byte) 241, (byte) 54, (byte) 158, (byte) 198, (byte) 203, (byte) 120,
              (byte) 24, (byte) 239, (byte) 226, (byte) 89, (byte) 188, (byte) 138, (byte) 71,
              (byte) 241, (byte) 38, (byte) 158, (byte) 196, (byte) 139, (byte) 120, (byte) 16,
              (byte) 239, (byte) 225, (byte) 57, (byte) 188, (byte) 134, (byte) 199, (byte) 240,
              (byte) 22, (byte) 158, (byte) 194, (byte) 75, (byte) 120, (byte) 8, (byte) 239,
              (byte) 224, (byte) 25, (byte) 188, (byte) 130, (byte) 71, (byte) 240, (byte) 6,
              (byte) 158, (byte) 192, (byte) 11, (byte) 120, (byte) 0
            });
  }

  @Test
  public void pkEncode_works() throws Exception {
    byte[] rho = new byte[MlDsaConstants.RHO_LENGTH];
    Arrays.fill(rho, (byte) 0xAA);
    VectorRq t1Bold = new VectorRq(ML_DSA_65_PARAMS.k);
    // Set a non-zero value in the first polynomial of t1Bold to test the loop starting index.
    t1Bold.vector[0].polynomial[0] = new RingZq(1023);

    byte[] pk = MlDsaMarshalUtil.pkEncode(rho, t1Bold, ML_DSA_65_PARAMS);

    assertThat(pk).hasLength(ML_DSA_65_PARAMS.pkLength);
    assertThat(Arrays.copyOf(pk, MlDsaConstants.RHO_LENGTH)).isEqualTo(rho);
    // Check the packed bytes from t1Bold.vector[0].polynomial[0]
    int offset = MlDsaConstants.RHO_LENGTH;
    assertThat(Arrays.copyOfRange(pk, offset, offset + 5))
        .isEqualTo(new byte[] {(byte) 255, (byte) 3, (byte) 0, (byte) 0, (byte) 0});
  }

  @Test
  public void skEncode_works() throws Exception {
    byte[] rho = new byte[MlDsaConstants.RHO_LENGTH];
    Arrays.fill(rho, (byte) 0xAA);
    byte[] capK = new byte[MlDsaConstants.K_LENGTH];
    Arrays.fill(capK, (byte) 0xBB);
    byte[] tr = new byte[MlDsaConstants.TR_LENGTH];
    Arrays.fill(tr, (byte) 0xCC);
    VectorRq s1Bold = new VectorRq(ML_DSA_65_PARAMS.l);
    s1Bold.vector[0].polynomial[0] = new RingZq(1);
    VectorRq s2Bold = new VectorRq(ML_DSA_65_PARAMS.k);
    s2Bold.vector[0].polynomial[0] = new RingZq(2);
    VectorRq t0Bold = new VectorRq(ML_DSA_65_PARAMS.k);
    t0Bold.vector[0].polynomial[0] = new RingZq(3);
    byte[] s1BoldTailPacked = new byte[32 * 4 * ML_DSA_65_PARAMS.l - 1];
    Arrays.fill(s1BoldTailPacked, (byte) 68);
    byte[] s2BoldTailPacked = new byte[32 * 4 * ML_DSA_65_PARAMS.k - 1];
    Arrays.fill(s2BoldTailPacked, (byte) 68);
    byte[] t0BoldTailPacked = new byte[32 * 13 * ML_DSA_65_PARAMS.k];
    System.arraycopy(
        new byte[] {-3, 15, 0, 2, 64, 0, 8, 0, 1, 32, 0, 4, -128}, 0, t0BoldTailPacked, 0, 13);
    for (int i = 1; i < 32 * ML_DSA_65_PARAMS.k; i++) {
      System.arraycopy(
          new byte[] {0, 16, 0, 2, 64, 0, 8, 0, 1, 32, 0, 4, -128}, 0, t0BoldTailPacked, 13 * i, 13);
    }

    SecretBytes sk =
        MlDsaMarshalUtil.skEncode(rho, capK, tr, s1Bold, s2Bold, t0Bold, ML_DSA_65_PARAMS);
    assertThat(sk.size()).isEqualTo(ML_DSA_65_PARAMS.skLength);
    byte[] skBytes = sk.toByteArray(InsecureSecretKeyAccess.get());
    assertThat(Arrays.copyOf(skBytes, MlDsaConstants.RHO_LENGTH)).isEqualTo(rho);
    assertThat(
            Arrays.copyOfRange(
                skBytes,
                MlDsaConstants.RHO_LENGTH,
                MlDsaConstants.RHO_LENGTH + MlDsaConstants.K_LENGTH))
        .isEqualTo(capK);
    assertThat(
            Arrays.copyOfRange(
                skBytes,
                MlDsaConstants.RHO_LENGTH + MlDsaConstants.K_LENGTH,
                MlDsaConstants.RHO_LENGTH + MlDsaConstants.K_LENGTH + MlDsaConstants.TR_LENGTH))
        .isEqualTo(tr);
    assertThat(
            skBytes[MlDsaConstants.RHO_LENGTH + MlDsaConstants.K_LENGTH + MlDsaConstants.TR_LENGTH])
        .isEqualTo((byte) 67);
    assertThat(
            Arrays.copyOfRange(
                skBytes,
                MlDsaConstants.RHO_LENGTH + MlDsaConstants.K_LENGTH + MlDsaConstants.TR_LENGTH + 1,
                MlDsaConstants.RHO_LENGTH
                    + MlDsaConstants.K_LENGTH
                    + MlDsaConstants.TR_LENGTH
                    + 32 * 4 * ML_DSA_65_PARAMS.l))
        .isEqualTo(s1BoldTailPacked);
    assertThat(
            skBytes[
                MlDsaConstants.RHO_LENGTH
                    + MlDsaConstants.K_LENGTH
                    + MlDsaConstants.TR_LENGTH
                    + 32 * 4 * ML_DSA_65_PARAMS.l])
        .isEqualTo((byte) 66);
    assertThat(
            Arrays.copyOfRange(
                skBytes,
                MlDsaConstants.RHO_LENGTH
                    + MlDsaConstants.K_LENGTH
                    + MlDsaConstants.TR_LENGTH
                    + 32 * 4 * ML_DSA_65_PARAMS.l
                    + 1,
                MlDsaConstants.RHO_LENGTH
                    + MlDsaConstants.K_LENGTH
                    + MlDsaConstants.TR_LENGTH
                    + 32 * 4 * ML_DSA_65_PARAMS.l
                    + 32 * 4 * ML_DSA_65_PARAMS.k))
        .isEqualTo(s2BoldTailPacked);
    assertThat(
            Arrays.copyOfRange(
                skBytes,
                MlDsaConstants.RHO_LENGTH
                    + MlDsaConstants.K_LENGTH
                    + MlDsaConstants.TR_LENGTH
                    + 32 * 4 * ML_DSA_65_PARAMS.l
                    + 32 * 4 * ML_DSA_65_PARAMS.k,
                skBytes.length))
        .isEqualTo(t0BoldTailPacked);
  }
}
