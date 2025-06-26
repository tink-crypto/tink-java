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

package com.google.crypto.tink.mac.internal;

import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ChunkedAesCmacFipsTest {

  @Test
  public void testFipsCompatibility() {
    assumeTrue(TinkFips.useOnlyFips());

    // In FIPS-mode we expect that creating a ChunkedAesCmacImpl fails.
    assertThrows(
        GeneralSecurityException.class,
        () -> ChunkedAesCmacImpl.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key));
  }

}
