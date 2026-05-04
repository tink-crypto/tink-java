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
import com.google.crypto.tink.util.Bytes;
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
  @Test
  public void testKeyMaterialTypeFromProto() throws Exception {
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL))
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.UNKNOWN_KEYMATERIAL);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC))
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.SYMMETRIC);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE))
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC))
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.KeyData.KeyMaterialType.REMOTE))
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.REMOTE);
  }

  @Test
  public void testOutputPrefixTypeFromProto() throws Exception {
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.UNKNOWN_PREFIX))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.UNKNOWN_PREFIX);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.TINK))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.TINK);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.LEGACY))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.LEGACY);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.RAW))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.RAW);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.CRUNCHY);
    assertThat(ProtoConversions.fromProto(com.google.crypto.tink.proto.OutputPrefixType.WITH_ID_REQUIREMENT))
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.WITH_ID_REQUIREMENT);
  }

  @Test
  public void testGetOutputPrefix() throws Exception {
    assertThat(ProtoConversions.getOutputPrefix(ProtoKeySerialization.OutputPrefixType.RAW, null))
        .isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(
            ProtoConversions.getOutputPrefix(
                ProtoKeySerialization.OutputPrefixType.TINK, 0x01020304))
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x01, 0x02, 0x03, 0x04}));
    assertThat(
            ProtoConversions.getOutputPrefix(
                ProtoKeySerialization.OutputPrefixType.LEGACY, 0x01020304))
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04}));
    assertThat(
            ProtoConversions.getOutputPrefix(
                ProtoKeySerialization.OutputPrefixType.CRUNCHY, 0x01020304))
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04}));
  }
}
