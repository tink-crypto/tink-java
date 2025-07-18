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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyProtoKeyTest {
  private static final SecretKeyAccess ACCESS = InsecureSecretKeyAccess.get();

  @Test
  public void testLegacyProtoKeyCreate() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /*idRequirement = */ null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThat(key.getSerialization(ACCESS)).isSameInstanceAs(serialization);
  }

  @Test
  public void testLegacyProtoKeyCreate_withIdRequirement() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.WITH_ID_REQUIREMENT,
            /* idRequirement= */ 0x12345678);
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThat(key.getSerialization(ACCESS)).isSameInstanceAs(serialization);
  }

  @Test
  public void testLegacyProtoKeyCreate_withNullIdRequirement_getOutputPrefixThrows()
      throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.WITH_ID_REQUIREMENT,
            /* idRequirement= */ 0x12345678);
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    // Keys with WITH_ID_REQUIREMENT do not have a generic way to get an "OutputPrefix". Hence, this
    // should not be called (instead, parsing should succeed and the key class should have a
    // "getOutputPrefix() or something similar)
    assertThrows(GeneralSecurityException.class, () -> key.getOutputPrefix());
  }

  @Test
  public void testLegacyProtoKey_getParameters() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /*idRequirement = */ null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThat(key.getSerialization(ACCESS)).isSameInstanceAs(serialization);

    assertThat(key.getParameters().toString()).contains("typeUrl=myTypeUrl");
    assertThat(key.getParameters().toString()).contains("outputPrefixType=RAW");
  }

  @Test
  public void testGetIdRequirementOrNull() throws Exception {
    // RAW
    LegacyProtoKey key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /*idRequirement = */ null),
            ACCESS);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[0]));
    // TINK
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                0x11223344),
            ACCESS);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x11223344);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {01, 0x11, 0x22, 0x33, 0x44}));

    // CRUNCHY
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.CRUNCHY,
                0x11223344),
            ACCESS);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x11223344);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {00, 0x11, 0x22, 0x33, 0x44}));

    // LEGACY
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.LEGACY,
                0x11223344),
            ACCESS);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x11223344);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {00, 0x11, 0x22, 0x33, 0x44}));
  }

  @Test
  public void constructorAccessCheck_symmetric_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement = */ null);
    assertThrows(
        GeneralSecurityException.class,
        () -> new LegacyProtoKey(serialization, /* access = */ null));
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThrows(GeneralSecurityException.class, () -> key.getSerialization(/* access = */ null));
  }

  @Test
  public void constructorAccessCheck_asymmetricPrivate_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement = */ null);
    assertThrows(
        GeneralSecurityException.class,
        () -> new LegacyProtoKey(serialization, /* access = */ null));
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThrows(GeneralSecurityException.class, () -> key.getSerialization(/* access = */ null));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void constructorAccessCheck_asymmetricPublic_works() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, /* access = */ null);
    key.getSerialization(/* access = */ null);
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void constructorAccessCheck_remote_works() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, /* access = */ null);
    key.getSerialization(/* access = */ null);
  }

  @Test
  public void testEquals() throws Exception {
    LegacyProtoKey key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                /* idRequirement = */ null),
            ACCESS);
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        /* idRequirement = */ null),
                    ACCESS)))
        .isTrue();

    // Different type url:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl2",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        /* idRequirement = */ null),
                    ACCESS)))
        .isFalse();

    // Different value:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.copyFrom(new byte[] {1}),
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        /* idRequirement = */ null),
                    ACCESS)))
        .isFalse();

    // Different KeyMaterialType:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.ASYMMETRIC_PRIVATE,
                        OutputPrefixType.RAW,
                        /* idRequirement = */ null),
                    ACCESS)))
        .isFalse();

    // Different OutputPrefixType:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.TINK,
                        123),
                    ACCESS)))
        .isFalse();
  }

  @Test
  public void testEquals_differentIdRequirement() throws Exception {
    LegacyProtoKey key123 =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                123),
            ACCESS);
    LegacyProtoKey key123b =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                123),
            ACCESS);
    LegacyProtoKey key124 =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                124),
            ACCESS);
    assertThat(key123.equalsKey(key123b)).isTrue();
    assertThat(key123.equalsKey(key124)).isFalse();
  }
}
