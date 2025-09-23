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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests that Conscrypt is available on non-Android platforms.
 *
 * <p>This test is not run on Android platforms.
 */
@RunWith(JUnit4.class)
public final class ConscryptAvailabilityTest {

  @Test
  public void nonAndroid_conscryptIsAvailable() {
    Assume.assumeFalse(Util.isAndroid());
    assertThat(Conscrypt.isAvailable()).isTrue();
  }
}
