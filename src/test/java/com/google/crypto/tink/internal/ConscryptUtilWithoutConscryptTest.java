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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ConscryptUtilWithoutConscryptTest {

  @Test
  public void providerOrNull_returnsProviderIfNotOnAndroid() throws Exception {
    if (TestUtil.isAndroid()) {
      // Android uses Conscrypt by default.
      Provider provider = ConscryptUtil.providerOrNull();
      assertThat(provider).isNotNull();
      assertThat(ConscryptUtil.isConscryptProvider(provider)).isTrue();
    } else {
      Provider provider = ConscryptUtil.providerOrNull();
      assertThat(provider).isNull();
    }
  }

  @Test
  public void providerWithReflectionOrNull_returnsProvderOnlyOnAndroid() throws Exception {
    Provider provider = ConscryptUtil.providerWithReflectionOrNull();
    assertThat(provider).isNull();
  }
}
