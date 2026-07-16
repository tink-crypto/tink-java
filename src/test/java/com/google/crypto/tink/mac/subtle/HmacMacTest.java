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
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.internal.HmacTestUtil;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HmacMac}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class HmacMacTest {

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> HmacMac.create(null));
  }

  @BeforeClass
  public static void setUp() throws Exception {
    // If Tink is built in FIPS-only mode, register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test HMAC in FIPS-mode without Conscrypt Provider", cause);
      }
    }

    hmacImplementationTestVectors =
        Arrays.copyOf(
            HmacTestUtil.HMAC_TEST_VECTORS,
            HmacTestUtil.HMAC_TEST_VECTORS.length + HmacTestUtil.PREFIXED_KEY_TYPES.length);
    System.arraycopy(
        HmacTestUtil.PREFIXED_KEY_TYPES,
        0,
        hmacImplementationTestVectors,
        HmacTestUtil.HMAC_TEST_VECTORS.length,
        HmacTestUtil.PREFIXED_KEY_TYPES.length);
  }

  @DataPoints("failingHmacTestVectors")
  public static final HmacTestVector[] HMAC_FAILING_TEST_VECTORS =
      HmacTestUtil.CREATE_VERIFICATION_FAILS_FAST;

  @DataPoints("allHmacTestVectors")
  public static HmacTestVector[] hmacImplementationTestVectors;

  @Theory
  public void computeHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmac = HmacMac.create(t.key);

    assertThat(hmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmac = HmacMac.create(t.key);

    hmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyHmac_throwsOnWrongTag(
      @FromDataPoints("failingHmacTestVectors") HmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmac = HmacMac.create(t.key);

    assertThrows(GeneralSecurityException.class, () -> hmac.verifyMac(t.tag, t.message));
  }
}
