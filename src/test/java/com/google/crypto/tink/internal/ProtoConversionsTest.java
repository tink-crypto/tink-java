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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.ProtoKeySerialization;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ProtoConversionsTest {

  @Test
  public void testKeyMaterialTypeToProto() throws Exception {
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.KeyMaterialType.UNKNOWN_KEYMATERIAL))
        .isEqualTo(com.google.crypto.tink.proto.KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.KeyMaterialType.SYMMETRIC))
        .isEqualTo(com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE))
        .isEqualTo(com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC))
        .isEqualTo(com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.KeyMaterialType.REMOTE))
        .isEqualTo(com.google.crypto.tink.proto.KeyData.KeyMaterialType.REMOTE);
  }

  @Test
  public void testOutputPrefixTypeToProto() throws Exception {
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.UNKNOWN_PREFIX))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.UNKNOWN_PREFIX);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.TINK))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.TINK);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.LEGACY))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.LEGACY);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.RAW))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.RAW);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.CRUNCHY))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY);
    assertThat(ProtoConversions.toProto(ProtoKeySerialization.OutputPrefixType.WITH_ID_REQUIREMENT))
        .isEqualTo(com.google.crypto.tink.proto.OutputPrefixType.WITH_ID_REQUIREMENT);
  }
}
