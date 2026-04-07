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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code ProtoKeySerialization} */
@RunWith(JUnit4.class)
public final class ProtoKeySerializationTest {
  @Test
  public void testCreationAndValues_basic() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {10, 11, 12}),
            ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            ProtoKeySerialization.OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThat(serialization.getValue()).isEqualTo(ByteString.copyFrom(new byte[] {10, 11, 12}));
    assertThat(serialization.getKeyMaterialType())
        .isEqualTo(ProtoKeySerialization.KeyMaterialType.SYMMETRIC);
    assertThat(serialization.getOutputPrefixType())
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.RAW);
    assertThat(serialization.getTypeUrl()).isEqualTo("myTypeUrl");
    assertThat(serialization.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void testIdRequirement_present() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final ProtoKeySerialization.KeyMaterialType keyMaterialType =
        ProtoKeySerialization.KeyMaterialType.SYMMETRIC;

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, ProtoKeySerialization.OutputPrefixType.TINK, 123);
    assertThat(serialization.getOutputPrefixType())
        .isEqualTo(ProtoKeySerialization.OutputPrefixType.TINK);
    assertThat(serialization.getIdRequirementOrNull()).isEqualTo(123);
  }

  @Test
  public void testCreationWithTypeUrlWithNonAsciiCharacter_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                /* typeUrl= */ "\t",
                ByteString.copyFrom(new byte[] {10, 11, 12}),
                ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
                ProtoKeySerialization.OutputPrefixType.RAW,
                /* idRequirement= */ null));
  }

  @Test
  public void testIdRequirement_presentMustMatchoutputPrefixType() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final ProtoKeySerialization.KeyMaterialType keyMaterialType =
        ProtoKeySerialization.KeyMaterialType.SYMMETRIC;

    Object unused =
        ProtoKeySerialization.create(
            typeUrl,
            value,
            keyMaterialType,
            ProtoKeySerialization.OutputPrefixType.RAW,
            /* idRequirement= */ null);
    unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, ProtoKeySerialization.OutputPrefixType.TINK, 123);
    unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, ProtoKeySerialization.OutputPrefixType.CRUNCHY, 123);
    unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, ProtoKeySerialization.OutputPrefixType.LEGACY, 123);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl, value, keyMaterialType, ProtoKeySerialization.OutputPrefixType.RAW, 123));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                ProtoKeySerialization.OutputPrefixType.TINK,
                /* idRequirement= */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                ProtoKeySerialization.OutputPrefixType.CRUNCHY,
                /* idRequirement= */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                ProtoKeySerialization.OutputPrefixType.LEGACY,
                /* idRequirement= */ null));
  }
}
