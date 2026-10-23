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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * RFC 4648 section 3.5 requires decoders to reject a final quantum whose unused bits are not zero.
 * Without that check a non-canonical string decodes to the same bytes as its canonical
 * equivalent, which for JWS/JWT inputs means two distinct compact serialisations verify against one
 * signature (signature malleability).
 */
@RunWith(JUnit4.class)
public final class Base64StrictDecodingTest {

  // RFC 7515 Appendix A.1.1 signature. The two strings differ only in the unused
  // trailing bits of the final character ('k' has zero, 'l' does not).
  private static final String CANONICAL = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  private static final String NON_CANONICAL = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl";

  @Test
  public void urlSafeDecode_canonicalSignature_isAccepted() {
    assertThat(Base64.urlSafeDecode(CANONICAL)).hasLength(32);
  }

  @Test
  public void urlSafeDecode_nonCanonicalTrailingBits_isRejected() {
    assertThrows(IllegalArgumentException.class, () -> Base64.urlSafeDecode(NON_CANONICAL));
  }

  @Test
  public void urlSafeDecode_validShortForms_stillDecode() {
    assertThat(Base64.urlSafeDecode("QQ")).hasLength(1);
    assertThat(Base64.urlSafeDecode("QUI")).hasLength(2);
    assertThat(Base64.urlSafeDecode("QUJD")).hasLength(3);
  }
}
