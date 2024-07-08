// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.internal.Util;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1VerifyConscryptWithoutConscryptTest {

  @Test
  public void android_worksOnApiLevel22AndNewer() {
    Assume.assumeTrue(Util.isAndroid());
    if (Util.getAndroidApiLevel() == null || Util.getAndroidApiLevel() <= 21) {
      assertThat(RsaSsaPkcs1VerifyConscrypt.isSupported()).isFalse();
      return;
    }
    assertThat(RsaSsaPkcs1VerifyConscrypt.isSupported()).isTrue();
  }

  @Test
  public void notAndroid_isNotSupported() {
    Assume.assumeFalse(Util.isAndroid());

    assertThat(RsaSsaPkcs1VerifyConscrypt.isSupported()).isFalse();
  }
}
