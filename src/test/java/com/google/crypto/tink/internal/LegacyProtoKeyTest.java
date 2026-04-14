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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyProtoKeyTest {
  private static final SecretKeyAccess ACCESS = InsecureSecretKeyAccess.get();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    SignatureConfig.register();
    AeadConfig.register();
  }

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

  @Test
  public void testMaybeGetPublicKey() throws Exception {
    String hexX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    String hexY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    String hexPrivateValue = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    EcdsaPublicKey protoPublicKey =
        EcdsaPublicKey.newBuilder()
            .setVersion(0)
            // X and Y are currently serialized with an extra zero at the beginning.
            .setX(ByteString.copyFrom(Hex.decode("00" + hexX)))
            .setY(ByteString.copyFrom(Hex.decode("00" + hexY)))
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P256)
                    .setEncoding(EcdsaSignatureEncoding.IEEE_P1363))
            .build();
    EcdsaPrivateKey protoPrivateKey =
        EcdsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            // privateValue is currently serialized with an extra zero at the beginning.
            .setKeyValue(ByteString.copyFrom(Hex.decode("00" + hexPrivateValue)))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    LegacyProtoKey privateKey = new LegacyProtoKey(serialization, ACCESS);

    Key publicKey = privateKey.maybeGetPublicKey();

    assertThat(publicKey).isInstanceOf(LegacyProtoKey.class);
    ProtoKeySerialization publicKeySerialization =
        ((LegacyProtoKey) publicKey).getSerialization(/* access= */ null);
    assertThat(publicKeySerialization.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPublicKey");
    assertThat(publicKeySerialization.getKeyMaterialTypeProto())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeySerialization.getOutputPrefixTypeProto()).isEqualTo(OutputPrefixType.TINK);
    assertThat(publicKeySerialization.getIdRequirementOrNull()).isEqualTo(123);

    EcdsaPublicKey obtainedProtoPublicKey =
        EcdsaPublicKey.parseFrom(
            publicKeySerialization.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(obtainedProtoPublicKey).isEqualTo(protoPublicKey);
  }

  @Test
  public void testMaybeGetPublicKey_failsIfNoPrivateKeyManager() throws Exception {
    LegacyProtoKey symmetricKey =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                123),
            ACCESS);

    assertThrows(GeneralSecurityException.class, symmetricKey::maybeGetPublicKey);
  }
}
