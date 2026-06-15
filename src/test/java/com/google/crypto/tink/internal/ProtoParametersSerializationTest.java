// Copyright 2022 Google LLC
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

import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code ProtoParametersSerialization} */
@RunWith(JUnit4.class)
public final class ProtoParametersSerializationTest {

  @Test
  public void testCreate_basic() throws Exception {
    ByteString value = ByteString.copyFrom(new byte[] {1, 2, 3});
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create("myTypeUrl", OutputPrefixType.RAW, value);
    assertThat(serialization.getTypeUrl()).isEqualTo("myTypeUrl");
    assertThat(serialization.getValue()).isEqualTo(value);
    assertThat(serialization.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
  }

  @Test
  public void testCreate_invalidTypeUrl_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoParametersSerialization.create(
                "some invalid typeurl", OutputPrefixType.RAW, ByteString.EMPTY));
  }

  @Test
  public void testGetOutputPrefixType() throws Exception {
    for (OutputPrefixType type :
        new OutputPrefixType[] {
          OutputPrefixType.UNKNOWN_PREFIX,
          OutputPrefixType.TINK,
          OutputPrefixType.LEGACY,
          OutputPrefixType.RAW,
          OutputPrefixType.CRUNCHY,
          OutputPrefixType.WITH_ID_REQUIREMENT
        }) {
      ProtoParametersSerialization serialization =
          ProtoParametersSerialization.create("myTypeUrl", type, ByteString.EMPTY);
      assertThat(serialization.getOutputPrefixType()).isEqualTo(type);
    }
  }
}
