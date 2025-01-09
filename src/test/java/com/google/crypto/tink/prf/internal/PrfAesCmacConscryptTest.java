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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Mac;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link PrfAesCmacConscrypt}. */
@RunWith(Theories.class)
public class PrfAesCmacConscryptTest {

  @DataPoints("AesCmacPrfTestVectors")
  public static final List<AesCmacPrfTestUtil.TestVector> testVectors =
      AesCmacPrfTestUtil.creatTestVectors();

  @DataPoints("WycheproofTestVectors")
  public static final List<AesCmacPrfTestUtil.TestVector> wycheproofTestVectors =
      AesCmacPrfWycheproofTestUtil.readTestVectors();

  @Before
  public void useConscrypt() throws Exception {
    if (!Util.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  private static boolean conscryptSupportsAesCmac() {
    if (Util.isAndroid()) {
      return Util.getAndroidApiLevel() >= 31;
    }
    // The open-source version of Conscrypt does not yet support AESCMAC.
    try {
      Mac unused = Mac.getInstance("AESCMAC");
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  @Theory
  public void createWithAesCmacPrfKey_compute_isCorrect(
      @FromDataPoints("AesCmacPrfTestVectors") AesCmacPrfTestUtil.TestVector testVector)
      throws Exception {
    // We don't use assumeTrue here because we don't want this to fail if Conscrypt does not
    // support AES-CMAC.
    if (!conscryptSupportsAesCmac()) {
      return;
    }

    Prf prf = PrfAesCmacConscrypt.create(testVector.key());

    assertThat(prf.compute(testVector.data(), testVector.outputLength())).isEqualTo(testVector.output());
  }

  @Theory
  public void wycheproofTestVectors_compute_isCorrect(
      @FromDataPoints("WycheproofTestVectors") AesCmacPrfTestUtil.TestVector testVector)
      throws Exception {
    // We don't use assumeTrue here because we don't want this to fail if Conscrypt does not
    // support AES-CMAC.
    if (!conscryptSupportsAesCmac()) {
      return;
    }

    Prf prf = PrfAesCmacConscrypt.create(testVector.key());

    assertThat(prf.compute(testVector.data(), testVector.outputLength()))
        .isEqualTo(testVector.output());
  }

  @Test
  public void useAesKeyOfSize192Bits_throws() throws Exception {
    assumeTrue(conscryptSupportsAesCmac());

    // Conscrypt's AES-CMAC implementation supports 192-bit keys, but Tink doesn't.
    // If this test fails, then either validation has to be added to PrfAesCmacConscrypt to reject
    // 192-bit keys, or 192-bits test vectors have to be added to
    // AesCmacPrfWycheproofTestUtil.readTestVectors.
    byte[] aes192Key = Random.randBytes(24);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(aes192Key.length),
                SecretBytes.copyFrom(aes192Key, InsecureSecretKeyAccess.get())));
  }

  @Test
  public void invalidAesKeySize_throws() throws Exception {
    assumeTrue(conscryptSupportsAesCmac());

    for (int n = 0; n < 70; n++) {
      final int keySize = n;
      if (keySize == 16 || keySize == 24 || keySize == 32) {
        continue;
      }
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              AesCmacPrfKey.create(
                  AesCmacPrfParameters.create(keySize),
                  SecretBytes.copyFrom(
                      Random.randBytes(keySize),
                      InsecureSecretKeyAccess.get())));
    }
  }

  @Test
  public void compute_outputLengthLargerThanBlockSize_throws() throws Exception {
    assumeTrue(conscryptSupportsAesCmac());

    int keySize = 16;
    Prf prf =
        PrfAesCmacConscrypt.create(
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(keySize),
                SecretBytes.copyFrom(
                    Random.randBytes(keySize),
                    InsecureSecretKeyAccess.get())));
    byte[] message = new byte[0];

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> prf.compute(message, /* outputLength= */ 17));
  }

  @Test
  public void compute_outputLengthZero_returnsEmptyArray() throws Exception {
    assumeTrue(conscryptSupportsAesCmac());

    int keySize = 16;
    Prf prf =
        PrfAesCmacConscrypt.create(
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(keySize),
                SecretBytes.copyFrom(
                    Random.randBytes(keySize),
                    InsecureSecretKeyAccess.get())));
    byte[] message = new byte[0];

    assertThat(prf.compute(message, /* outputLength= */ 0)).isEmpty();
  }

  @Test
  public void compute_bitFlipInMessage_outputIsDifferent() throws Exception {
    assumeTrue(conscryptSupportsAesCmac());

    int keySize = 16;
    Prf prf =
        PrfAesCmacConscrypt.create(
            AesCmacPrfKey.create(
                AesCmacPrfParameters.create(keySize),
                SecretBytes.copyFrom(
                    Random.randBytes(keySize),
                    InsecureSecretKeyAccess.get())));
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
