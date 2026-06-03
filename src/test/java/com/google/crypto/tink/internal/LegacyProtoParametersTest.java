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

import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.protobuf.ByteString;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyProtoParametersTest {

  @Test
  public void testConstructorAndGetSerialization() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "TypeUrl",
            OutputPrefixType.TINK,
            ByteString.copyFromUtf8("value"));
    LegacyProtoParameters parameters = new LegacyProtoParameters(serialization);
    assertThat(parameters.getSerialization()).isSameInstanceAs(serialization);
  }

  @Test
  public void testHasIdRequirement() throws Exception {
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.TINK, ByteString.EMPTY))
                .hasIdRequirement())
        .isTrue();
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.CRUNCHY, ByteString.EMPTY))
                .hasIdRequirement())
        .isTrue();
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.LEGACY, ByteString.EMPTY))
                .hasIdRequirement())
        .isTrue();
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.WITH_ID_REQUIREMENT, ByteString.EMPTY))
                .hasIdRequirement())
        .isTrue();
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.RAW, ByteString.EMPTY))
                .hasIdRequirement())
        .isFalse();
    assertThat(
            new LegacyProtoParameters(
                    ProtoParametersSerialization.create(
                        "TypeUrl", OutputPrefixType.UNKNOWN_PREFIX, ByteString.EMPTY))
                .hasIdRequirement())
        .isTrue();
  }

  @Test
  public void testEquals() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("value"));
    ProtoParametersSerialization serialization1Copy =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("value"));
    ProtoParametersSerialization serializationDifferentUrl =
        ProtoParametersSerialization.create(
            "DifferentTypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("value"));
    ProtoParametersSerialization serializationDifferentPrefix =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.RAW, ByteString.copyFromUtf8("value"));
    ProtoParametersSerialization serializationDifferentValue =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("different value"));

    LegacyProtoParameters parameters1 = new LegacyProtoParameters(serialization1);
    LegacyProtoParameters parameters1Copy = new LegacyProtoParameters(serialization1Copy);
    LegacyProtoParameters parametersDifferentUrl = new LegacyProtoParameters(serializationDifferentUrl);
    LegacyProtoParameters parametersDifferentPrefix = new LegacyProtoParameters(serializationDifferentPrefix);
    LegacyProtoParameters parametersDifferentValue = new LegacyProtoParameters(serializationDifferentValue);

    assertThat(parameters1).isEqualTo(parameters1Copy);
    assertThat(parameters1Copy).isEqualTo(parameters1);

    assertThat(parameters1).isNotEqualTo(parametersDifferentUrl);
    assertThat(parameters1).isNotEqualTo(parametersDifferentPrefix);
    assertThat(parameters1).isNotEqualTo(parametersDifferentValue);

    assertThat(parameters1).isNotEqualTo(null);
    assertThat(parameters1.equals((Object) "some string")).isFalse();
  }

  @Test
  public void testHashCode() throws Exception {
    ProtoParametersSerialization serialization1 =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("value"));
    ProtoParametersSerialization serialization1Copy =
        ProtoParametersSerialization.create(
            "TypeUrl", OutputPrefixType.TINK, ByteString.copyFromUtf8("value"));

    LegacyProtoParameters parameters1 = new LegacyProtoParameters(serialization1);
    LegacyProtoParameters parameters1Copy = new LegacyProtoParameters(serialization1Copy);

    assertThat(parameters1.hashCode()).isEqualTo(parameters1Copy.hashCode());
  }

  @Test
  public void testToString() throws Exception {
    LegacyProtoParameters parameters =
        new LegacyProtoParameters(
            ProtoParametersSerialization.create(
                "myTypeUrl", OutputPrefixType.TINK, ByteString.EMPTY));
    assertThat(parameters.toString()).isEqualTo("(typeUrl=myTypeUrl, outputPrefixType=TINK)");
  }
}
