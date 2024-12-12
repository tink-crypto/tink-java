// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.internal.AesCmacPrfTestUtil;
import com.google.crypto.tink.prf.internal.AesCmacPrfWycheproofTestUtil;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.List;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link PrfAesCmac}. */
@RunWith(Theories.class)
public class PrfAesCmacTest {

  private static final int KEY_SIZE = 16;

  @DataPoints("AesCmacPrfTestVectors")
  public static final List<AesCmacPrfTestUtil.TestVector> testVectors =
      AesCmacPrfTestUtil.creatTestVectors();

  @DataPoints("WycheproofTestVectors")
  public static final List<AesCmacPrfTestUtil.TestVector> wycheproofTestVectors =
      AesCmacPrfWycheproofTestUtil.readTestVectors();

  @Theory
  public void calcN_returnsNumberOfAesBlocks() throws Exception {
    // AES block size is 16 bytes.
    assertThat(PrfAesCmac.calcN(0)).isEqualTo(1);
    assertThat(PrfAesCmac.calcN(1)).isEqualTo(1);
    assertThat(PrfAesCmac.calcN(16)).isEqualTo(1);
    assertThat(PrfAesCmac.calcN(17)).isEqualTo(2);
    assertThat(PrfAesCmac.calcN(32)).isEqualTo(2);
    assertThat(PrfAesCmac.calcN(33)).isEqualTo(3);
    assertThat(PrfAesCmac.calcN(48)).isEqualTo(3);
    assertThat(PrfAesCmac.calcN(49)).isEqualTo(4);
    assertThat(PrfAesCmac.calcN(0x7FFFFFF0)).isEqualTo(0x07FFFFFF);
    assertThat(PrfAesCmac.calcN(0x7FFFFFF1)).isEqualTo(0x08000000);
    assertThat(PrfAesCmac.calcN(Integer.MAX_VALUE)).isEqualTo(0x08000000);
  }

  @Theory
  public void compute_isCorrect(
      @FromDataPoints("AesCmacPrfTestVectors") AesCmacPrfTestUtil.TestVector testVector)
      throws Exception {
    Prf prf =
        new PrfAesCmac(testVector.key().getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()));

    assertThat(prf.compute(testVector.data(), testVector.outputLength())).isEqualTo(testVector.output());
  }

  @Theory
  public void createWithAesCmacPrfKey_compute_isCorrect(
      @FromDataPoints("AesCmacPrfTestVectors") AesCmacPrfTestUtil.TestVector testVector)
      throws Exception {
    Prf prf = PrfAesCmac.create(testVector.key());

    assertThat(prf.compute(testVector.data(), testVector.outputLength())).isEqualTo(testVector.output());
  }

  @Theory
  public void wycheproofTestVectors_compute_isCorrect(
      @FromDataPoints("WycheproofTestVectors") AesCmacPrfTestUtil.TestVector testVector)
      throws Exception {
    Prf prf = PrfAesCmac.create(testVector.key());

    assertThat(prf.compute(testVector.data(), testVector.outputLength()))
        .isEqualTo(testVector.output());
  }

  @Theory
  public void compute_outputLengthTooLarge_throws() throws Exception {
    Prf prf = new PrfAesCmac(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
    byte[] message = new byte[0];

    assertThrows(InvalidAlgorithmParameterException.class, () -> prf.compute(message, 17));
  }

  @Theory
  public void compute_bitFlipInMessage_outputIsDifferent() throws Exception {
    byte[] key = Random.randBytes(KEY_SIZE);
    Prf prf = new PrfAesCmac(key);
    byte[] message = Random.randBytes(20);
    int outputLength = 16;

    byte[] output = prf.compute(message, outputLength);

    for (int b = 0; b < message.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedMessage = Arrays.copyOf(message, message.length);
        modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));

        byte[] outputOfModifiedMessage = prf.compute(modifiedMessage, outputLength);

        assertThat(outputOfModifiedMessage).isNotEqualTo(output);
      }
    }
  }
}
