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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.subtle.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrehashFormatTest {

  @Test
  public void getPrehashPrefix_returnsStartByteAndBigEndianId() {
    assertThat(PrehashFormat.getPrehashPrefix(0x01020304)).isEqualTo(Hex.decode("ff01020304"));
    assertThat(PrehashFormat.getPrehashPrefix(0x00000000)).isEqualTo(Hex.decode("ff00000000"));
    assertThat(PrehashFormat.getPrehashPrefix(0x7fffffff)).isEqualTo(Hex.decode("ff7fffffff"));
    assertThat(PrehashFormat.getPrehashPrefix(0x80000000)).isEqualTo(Hex.decode("ff80000000"));
    assertThat(PrehashFormat.getPrehashPrefix(0xffffffff)).isEqualTo(Hex.decode("ffffffffff"));
  }

  @Test
  public void getPrehashPrefix_hasPrefixSizeAndStartsWithStartByte() {
    byte[] prefix = PrehashFormat.getPrehashPrefix(123);

    assertThat(prefix).hasLength(PrehashFormat.PREHASH_PREFIX_SIZE);
    assertThat(prefix[0]).isEqualTo(PrehashFormat.PREHASH_START_BYTE);
  }
}
