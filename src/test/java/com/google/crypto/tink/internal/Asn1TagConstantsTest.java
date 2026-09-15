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

package com.google.crypto.tink.internal;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Asn1TagConstants}. */
@RunWith(JUnit4.class)
public final class Asn1TagConstantsTest {

  @Test
  public void tagConstants_matchAsn1Spec() {
    assertEquals((byte) 0x02, Asn1TagConstants.TAG_INTEGER);
    assertEquals((byte) 0x03, Asn1TagConstants.TAG_BIT_STRING);
    assertEquals((byte) 0x04, Asn1TagConstants.TAG_OCTET_STRING);
    assertEquals((byte) 0x05, Asn1TagConstants.TAG_NULL);
    assertEquals((byte) 0x06, Asn1TagConstants.TAG_OBJECT_IDENTIFIER);
    assertEquals((byte) 0x30, Asn1TagConstants.TAG_SEQUENCE);
    assertEquals((byte) 0x00, Asn1TagConstants.NULL_BYTE);
  }
}
