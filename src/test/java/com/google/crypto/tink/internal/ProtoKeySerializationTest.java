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

import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
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
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement = */ null);

    assertThat(serialization.getValue()).isEqualTo(ByteString.copyFrom(new byte[] {10, 11, 12}));
    assertThat(serialization.getKeyMaterialTypeProto()).isEqualTo(KeyMaterialType.SYMMETRIC);
    assertThat(serialization.getOutputPrefixTypeProto()).isEqualTo(OutputPrefixType.RAW);
    assertThat(serialization.getTypeUrl()).isEqualTo("myTypeUrl");
    assertThat(serialization.getIdRequirementOrNull()).isNull();
    assertThat(serialization.getObjectIdentifier())
        .isEqualTo(Bytes.copyFrom("myTypeUrl".getBytes(UTF_8)));
  }

  @Test
  public void testIdRequirement_present() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final KeyMaterialType keyMaterialType = KeyMaterialType.SYMMETRIC;

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.TINK, 123);
    assertThat(serialization.getOutputPrefixTypeProto()).isEqualTo(OutputPrefixType.TINK);
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
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement= */ null));
  }

  @Test
  public void testIdRequirement_presentMustMatchoutputPrefixType() throws Exception {
    final String typeUrl = "myTypeUrl";
    final ByteString value = ByteString.copyFrom(new byte[] {10, 11, 12});
    final KeyMaterialType keyMaterialType = KeyMaterialType.SYMMETRIC;

    Object unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, OutputPrefixType.RAW, /* idRequirement= */ null);
    unused =
        ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.TINK, 123);
    unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, OutputPrefixType.CRUNCHY, 123);
    unused =
        ProtoKeySerialization.create(typeUrl, value, keyMaterialType, OutputPrefixType.LEGACY, 123);
    unused =
        ProtoKeySerialization.create(
            typeUrl, value, keyMaterialType, OutputPrefixType.WITH_ID_REQUIREMENT, 123);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl, value, keyMaterialType, OutputPrefixType.RAW, 123));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.TINK,
                /* idRequirement = */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.CRUNCHY,
                /* idRequirement = */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.LEGACY,
                /* idRequirement = */ null));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ProtoKeySerialization.create(
                typeUrl,
                value,
                keyMaterialType,
                OutputPrefixType.WITH_ID_REQUIREMENT,
                /* idRequirement= */ null));
  }

  @Test
  public void testApiConversions_rawSymmetric() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
            null);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_rawAsymmetricPrivate() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
            null);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_rawAsymmetricPublic() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
            null);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_rawRemote() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
            null);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_tinkSymmetric() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_tinkAsymmetricPrivate() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_tinkAsymmetricPublic() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_tinkRemote() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_legacySymmetric() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_legacyAsymmetricPrivate() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_legacyAsymmetricPublic() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_legacyRemote() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.LEGACY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_crunchySymmetric() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_crunchyAsymmetricPrivate() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_crunchyAsymmetricPublic() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_crunchyRemote() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.REMOTE,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.CRUNCHY,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }

  @Test
  public void testApiConversions_withIdRequirement() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization apiSerialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "typeUrl",
            ByteString.copyFrom(new byte[] {1, 2, 3}),
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.WITH_ID_REQUIREMENT,
            123);
    ProtoKeySerialization internalSerialization =
        ProtoKeySerialization.createFromPublic(apiSerialization);
    com.google.crypto.tink.ProtoKeySerialization apiSerialization2 =
        internalSerialization.toPublic();
    assertThat(apiSerialization2.getTypeUrl()).isEqualTo(apiSerialization.getTypeUrl());
    assertThat(apiSerialization2.getValue()).isEqualTo(apiSerialization.getValue());
    assertThat(apiSerialization2.getKeyMaterialType())
        .isEqualTo(apiSerialization.getKeyMaterialType());
    assertThat(apiSerialization2.getOutputPrefixType())
        .isEqualTo(apiSerialization.getOutputPrefixType());
    assertThat(apiSerialization2.getIdRequirementOrNull())
        .isEqualTo(apiSerialization.getIdRequirementOrNull());
  }
}
