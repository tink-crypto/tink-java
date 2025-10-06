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
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ConscryptUtilTest {

  private static boolean conscryptIsAvailable() {
    try {
      return Conscrypt.isAvailable();
    } catch (Throwable e) {
      return false;
    }
  }

  @BeforeClass
  public static void setUp() {
    if (!TestUtil.isAndroid() && conscryptIsAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void providerOrNull_returnsConscryptProviderIfAvailable() throws Exception {
    if (!TestUtil.isAndroid() && !conscryptIsAvailable()) {
      assertThat(ConscryptUtil.providerOrNull()).isNull();
      return;
    }
    Provider provider = ConscryptUtil.providerOrNull();
    assertThat(provider).isNotNull();
    assertThat(ConscryptUtil.isConscryptProvider(provider)).isTrue();
  }

  @Test
  public void providerWithReflectionOrNull_returnsConscryptProviderIfNotOnAndroidAndAvailable()
      throws Exception {
    if (TestUtil.isAndroid()) {
      // providerWithReflectionOrNull does not work on Android
      Provider provider = ConscryptUtil.providerWithReflectionOrNull();
      assertThat(provider).isNull();
    } else if (!conscryptIsAvailable()) {
      Provider provider = ConscryptUtil.providerWithReflectionOrNull();
      assertThat(provider).isNull();
    } else {
      Provider provider = ConscryptUtil.providerWithReflectionOrNull();
      assertThat(provider).isNotNull();
      assertThat(ConscryptUtil.isConscryptProvider(provider)).isTrue();
    }
  }

  @Test
  public void isConscryptProviderWithDifferentName_returnsFalse() throws Exception {
    if (TestUtil.isAndroid() || !conscryptIsAvailable()) {
      return;
    }
    // isConscryptProvider uses the name of the provider to determine if it is Conscrypt.
    // We don't expect users to rename the provider.
    Provider renamedProvider = Conscrypt.newProviderBuilder().setName("notConscrypt").build();
    assertThat(ConscryptUtil.isConscryptProvider(renamedProvider)).isFalse();
  }
}
