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

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ParametersSerializer}. */
@RunWith(JUnit4.class)
public final class ParametersSerializerTest {

  @Immutable
  private static class ExampleParameters extends Parameters {
    @Override
    public boolean hasIdRequirement() {
      return false;
    }
  }

  private static ProtoParametersSerialization serialize(ExampleParameters k)
      throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        "typeUrl",
        OutputPrefixType.RAW,
        ByteString.EMPTY);
  }

  @Test
  public void createSerializer_works() throws Exception {
    Object unused =
        ParametersSerializer.create(ParametersSerializerTest::serialize, ExampleParameters.class);
  }

  @Test
  public void createSerializer_serializeKey_works() throws Exception {
    ParametersSerializer<ExampleParameters> serializer =
        ParametersSerializer.create(ParametersSerializerTest::serialize, ExampleParameters.class);
    assertThat(serializer.serializeParameters(new ExampleParameters())).isNotNull();
  }

  @Test
  public void createSerializer_classes_work() throws Exception {
    ParametersSerializer<ExampleParameters> serializer =
        ParametersSerializer.create(ParametersSerializerTest::serialize, ExampleParameters.class);
    assertThat(serializer.getParametersClass()).isEqualTo(ExampleParameters.class);
    assertThat(serializer.getSerializationClass()).isEqualTo(ProtoParametersSerialization.class);
  }
}
