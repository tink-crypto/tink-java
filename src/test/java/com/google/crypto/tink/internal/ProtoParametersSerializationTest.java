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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.TestProto;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code ProtoParametersSerialization} */
@RunWith(JUnit4.class)
public final class ProtoParametersSerializationTest {
  @Test
  public void testCreationAndValues_basic() throws Exception {
    ByteString value = ByteString.copyFrom(new byte[] {1, 2, 3});
    KeyTemplate template = KeyTemplate.newBuilder().setTypeUrl("myTypeUrl").setValue(value).build();
    ProtoParametersSerialization serialization = ProtoParametersSerialization.create(template);
    assertThat(serialization.getKeyTemplate()).isEqualTo(template);
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("myTypeUrl".getBytes(UTF_8)));
    assertThat(serialization.getTypeUrl()).isEqualTo("myTypeUrl");
    assertThat(serialization.getValue()).isEqualTo(value);
  }

  @Test
  public void testCreationFromParts_basic() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "typeUrl", OutputPrefixType.RAW, TestProto.newBuilder().setNum(13234).build());
    assertThat(serialization.getKeyTemplate().getTypeUrl()).isEqualTo("typeUrl");
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("typeUrl".getBytes(UTF_8)));
    assertThat(serialization.getKeyTemplate().getOutputPrefixType())
        .isEqualTo(OutputPrefixType.RAW);
    TestProto parsedProto = TestProto.parseFrom(serialization.getKeyTemplate().getValue());
    assertThat(parsedProto.getNum()).isEqualTo(13234);
    TestProto parsedProto2 = TestProto.parseFrom(serialization.getValue());
    assertThat(parsedProto2.getNum()).isEqualTo(13234);
    assertThat(serialization.getTypeUrl()).isEqualTo("typeUrl");
  }

  @Test
  public void testCreationFromTemplate_invalidTypeUrl_throws() throws Exception {
    KeyTemplate template = KeyTemplate.newBuilder().setTypeUrl("some invalid typeurl").build();
    assertThrows(TinkBugException.class, () -> ProtoParametersSerialization.create(template));
  }

  @Test
  public void testCheckedCreationAndValues_basic() throws Exception {
    KeyTemplate template = KeyTemplate.newBuilder().setTypeUrl("myTypeUrl").build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.checkedCreate(template);
    assertThat(serialization.getKeyTemplate()).isEqualTo(template);
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("myTypeUrl".getBytes(UTF_8)));
  }

  @Test
  public void testGetOutputPrefixType() throws Exception {
    KeyTemplate tinkTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl("myTypeUrl")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    ProtoParametersSerialization tinkSerialization =
        ProtoParametersSerialization.create(tinkTemplate);
    assertThat(tinkSerialization.getOutputPrefixType())
        .isEqualTo(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK);

    KeyTemplate legacyTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl("myTypeUrl")
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    ProtoParametersSerialization legacySerialization =
        ProtoParametersSerialization.create(legacyTemplate);
    assertThat(legacySerialization.getOutputPrefixType())
        .isEqualTo(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY);

    KeyTemplate rawTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl("myTypeUrl")
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    ProtoParametersSerialization rawSerialization =
        ProtoParametersSerialization.create(rawTemplate);
    assertThat(rawSerialization.getOutputPrefixType())
        .isEqualTo(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW);

    KeyTemplate crunchyTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl("myTypeUrl")
            .setOutputPrefixType(OutputPrefixType.CRUNCHY)
            .build();
    ProtoParametersSerialization crunchySerialization =
        ProtoParametersSerialization.create(crunchyTemplate);
    assertThat(crunchySerialization.getOutputPrefixType())
        .isEqualTo(com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY);

    KeyTemplate withIdRequirementTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl("myTypeUrl")
            .setOutputPrefixType(OutputPrefixType.WITH_ID_REQUIREMENT)
            .build();
    ProtoParametersSerialization withIdRequirementSerialization =
        ProtoParametersSerialization.create(withIdRequirementTemplate);
    assertThat(withIdRequirementSerialization.getOutputPrefixType())
        .isEqualTo(
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.WITH_ID_REQUIREMENT);
  }

  @Test
  public void testCheckedCreationFromTemplate_invalidTypeUrl_throws() throws Exception {
    KeyTemplate template = KeyTemplate.newBuilder().setTypeUrl("some invalid typeurl").build();
    assertThrows(
        GeneralSecurityException.class, () -> ProtoParametersSerialization.checkedCreate(template));
  }
}
