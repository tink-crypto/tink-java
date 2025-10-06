// Copyright 2024 Google LLC
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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.testing.TestUtil;
import java.security.Provider;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ConscryptUtilWithoutInstallingConscryptTest {

  private static boolean conscryptIsAvailable() {
    try {
      return Conscrypt.isAvailable();
    } catch (Throwable e) {
      return false;
    }
  }

  @Test
  public void providerOrNull_returnsProviderOnlyOnAndroid() throws Exception {
    if (TestUtil.isAndroid()) {
      // Android uses Conscrypt by default.
      Provider provider = ConscryptUtil.providerOrNull();
      assertThat(provider).isNotNull();
      assertThat(ConscryptUtil.isConscryptProvider(provider)).isTrue();
    } else {
      // Conscrypt is not installed.
      Provider provider = ConscryptUtil.providerOrNull();
      assertThat(provider).isNull();
    }
  }

  @Test
  public void providerWithReflectionOrNull_returnsProviderIfNotOnAndroidAndConscryptIsAvailable()
      throws Exception {
    Assume.assumeFalse(TestUtil.isAndroid() || conscryptIsAvailable());

    if (TestUtil.isAndroid()) {
      // providerWithReflectionOrNull does not work on Android
      Provider provider = ConscryptUtil.providerWithReflectionOrNull();
      assertThat(provider).isNull();
    } else {
      Provider provider = ConscryptUtil.providerWithReflectionOrNull();
      assertThat(provider).isNotNull();
      assertThat(ConscryptUtil.isConscryptProvider(provider)).isTrue();

      // Make a call to Conscrypt to make sure it is present in the binary.
      // But we don't install it.
      Conscrypt.checkAvailability();
    }
  }
}
