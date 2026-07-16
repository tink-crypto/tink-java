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

package com.google.crypto.tink.mac.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil.AesCmacTestVector;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link AesCmacMac}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class AesCmacMacTest {

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> AesCmacMac.create(null));
  }

  @DataPoints("allAesCmacTestVectors")
  public static final AesCmacTestVector[] CMAC_IMPLEMENTATION_TEST_VECTORS =
      new AesCmacTestVector[] {
        AesCmacTestUtil.RFC_TEST_VECTOR_0,
        AesCmacTestUtil.RFC_TEST_VECTOR_1,
        AesCmacTestUtil.RFC_TEST_VECTOR_2,
        AesCmacTestUtil.NOT_OVERFLOWING_INTERNAL_STATE,
        AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE,
        AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE_TWICE,
        AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_ONCE,
        AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_TWICE,
        AesCmacTestUtil.SHORTER_TAG,
        AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_LEGACY,
        AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_TINK,
        AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_CRUNCHY,
        AesCmacTestUtil.LONG_KEY_TEST_VECTOR,
      };

  @DataPoints("failingAesCmacTestVectors")
  public static final AesCmacTestVector[] CMAC_FAILING_TEST_VECTORS =
      new AesCmacTestVector[] {
        AesCmacTestUtil.WRONG_PREFIX_TAG_LEGACY,
        AesCmacTestUtil.WRONG_PREFIX_TAG_TINK,
        AesCmacTestUtil.TAG_TOO_SHORT
      };

  @Theory
  public void computeAesCmac_isCorrect(@FromDataPoints("allAesCmacTestVectors") AesCmacTestVector t)
      throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = AesCmacMac.create(t.key);

    assertThat(aesCmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyAesCmac_isCorrect(@FromDataPoints("allAesCmacTestVectors") AesCmacTestVector t)
      throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = AesCmacMac.create(t.key);

    aesCmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyAesCmac_throwsOnWrongTag(
      @FromDataPoints("failingAesCmacTestVectors") AesCmacTestVector t) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = AesCmacMac.create(t.key);

    assertThrows(GeneralSecurityException.class, () -> aesCmac.verifyMac(t.tag, t.message));
  }
}
