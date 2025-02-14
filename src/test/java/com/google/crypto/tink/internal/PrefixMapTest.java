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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PrefixMapTest {

  @Test
  public void basic0BytePrefix_works() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>().put(Bytes.copyFrom(new byte[0]), 123).build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4})).containsExactly(123);
  }

  @Test
  public void basic5BytePrefix_works() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 123)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}))
        .containsExactly(123);
  }

  @Test
  public void multiple0Bytes_works() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[0]), 123)
            .put(Bytes.copyFrom(new byte[0]), 456)
            .put(Bytes.copyFrom(new byte[0]), 7)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4}))
        .containsExactly(123, 456, 7)
        .inOrder();
  }

  @Test
  public void multiple5BytePrefix_works() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 123)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 456)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 7)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}))
        .containsExactly(123, 456, 7)
        .inOrder();
  }

  @Test
  public void first5Then0BytePrefixes() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[0]), 123)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 5123)
            .put(Bytes.copyFrom(new byte[0]), 456)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 5456)
            .put(Bytes.copyFrom(new byte[0]), 7)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 57)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4, 5, 6, 7}))
        .containsExactly(5123, 5456, 57, 123, 456, 7)
        .inOrder();
  }

  @Test
  public void multiple5BytesPicksCorrectOne() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 12)
            .put(Bytes.copyFrom(new byte[] {2, 2, 3, 4, 5}), 22)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 4, 5}), 32)
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 122)
            .put(Bytes.copyFrom(new byte[] {2, 2, 3, 4, 5}), 222)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 4, 5}), 322)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3, 4, 5, 6, 7}))
        .containsExactly(12, 122)
        .inOrder();
  }

  @Test
  public void nothingMatches_isEmpty() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 12)
            .put(Bytes.copyFrom(new byte[] {2, 2, 3, 4, 5}), 22)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 4, 5}), 32)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {4, 2, 3, 4, 5, 6, 7})).isEmpty();
  }

  @Test
  public void no5ByteMatches_givesStill0ByteMatches() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 4, 5}), 12)
            .put(Bytes.copyFrom(new byte[] {2, 2, 3, 4, 5}), 22)
            .put(Bytes.copyFrom(new byte[] {}), 77)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 4, 5}), 32)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {4, 2, 3, 4, 5, 6, 7})).containsExactly(77);
  }

  @Test
  public void shortByteArray_givesZeroBytePrefixes() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 0, 0}), 12)
            .put(Bytes.copyFrom(new byte[] {}), 22)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 0, 0}), 32)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {1, 2, 3})).containsExactly(22);
  }

  @Test
  public void emptyByteArray_givesZeroBytePrefixes() throws Exception {
    PrefixMap<Integer> map =
        new PrefixMap.Builder<Integer>()
            .put(Bytes.copyFrom(new byte[] {1, 2, 3, 0, 0}), 12)
            .put(Bytes.copyFrom(new byte[] {}), 22)
            .put(Bytes.copyFrom(new byte[] {3, 2, 3, 0, 0}), 32)
            .build();
    assertThat(map.getAllWithMatchingPrefix(new byte[] {})).containsExactly(22);
  }

  @Test
  public void oneBytePrefixThrows() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> new PrefixMap.Builder<Integer>().put(Bytes.copyFrom(new byte[] {1}), 12).build());
  }
}
