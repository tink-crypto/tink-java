// Copyright 2024 Google Inc.
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

import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrfAesCmacFipsTest {

  private static final int KEY_SIZE = 16;

  @Test
  public void testFipsCompatibility() throws Exception {
    assumeTrue(TinkFips.useOnlyFips());

    // In FIPS-mode we expect that creating a PrfAesCmac fails.
    assertThrows(
        GeneralSecurityException.class,
        () -> new PrfAesCmac(Random.randBytes(KEY_SIZE)));
  }

}
