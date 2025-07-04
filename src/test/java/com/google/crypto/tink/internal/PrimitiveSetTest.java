// Copyright 2017 Google LLC
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrimitiveSet. */
@RunWith(JUnit4.class)
public class PrimitiveSetTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    AeadConfig.register();
    HmacKeyManager.register(true);
  }

  com.google.crypto.tink.Key getKeyFromProtoKey(Key key) throws GeneralSecurityException {
    @Nullable Integer idRequirement = key.getKeyId();
    if (key.getOutputPrefixType() == OutputPrefixType.RAW) {
      idRequirement = null;
    }
    return MutableSerializationRegistry.globalInstance()
        .parseKeyWithLegacyFallback(
            ProtoKeySerialization.create(
                key.getKeyData().getTypeUrl(),
                key.getKeyData().getValue(),
                key.getKeyData().getKeyMaterialType(),
                key.getOutputPrefixType(),
                idRequirement),
            InsecureSecretKeyAccess.get());
  }

  @Test
  public void testGetKeysetHandle() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet pset =
        PrimitiveSet.newBuilder()
            .add(getKeyFromProtoKey(key1), key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getKeysetHandle().size()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getPrimary().getId()).isEqualTo(2);
    assertThat(pset.getKeysetHandle().getAt(0).getId()).isEqualTo(1);
    assertThat(pset.getKeysetHandle().getAt(0).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(1);
    assertThat(pset.getKeysetHandle().getAt(0).isPrimary()).isFalse();
    assertThat(pset.getKeysetHandle().getAt(1).getId()).isEqualTo(2);
    assertThat(pset.getKeysetHandle().getAt(1).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(1).getKey().getIdRequirementOrNull()).isEqualTo(null);
    assertThat(pset.getKeysetHandle().getAt(1).isPrimary()).isTrue();
    assertThat(pset.getKeysetHandle().getAt(2).getId()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getAt(2).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(2).getKey().getIdRequirementOrNull()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getAt(2).isPrimary()).isFalse();
  }

  @Test
  public void testAddFullPrimitive_throwsOnDoublePrimaryAdd() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    assertThrows(
        IllegalStateException.class,
        () ->
            PrimitiveSet.newBuilder()
                .addPrimary(getKeyFromProtoKey(key1), key1)
                .addPrimary(getKeyFromProtoKey(key2), key2)
                .build());
  }

  @Test
  public void testNoPrimary_getPrimaryReturnsNull() throws Exception {
    Key key =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    PrimitiveSet pset = PrimitiveSet.newBuilder().add(getKeyFromProtoKey(key), key).build();
    assertThat(pset.getKeysetHandle().getPrimary()).isNull();
  }

  @Test
  public void testEntryGetParametersToString() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();

    PrimitiveSet pset =
        PrimitiveSet.newBuilder().addPrimary(getKeyFromProtoKey(key1), key1).build();
    assertThat(pset.getKeysetHandle().getAt(0).getKey().getParameters().toString())
        .isEqualTo("(typeUrl=typeUrl1, outputPrefixType=TINK)");
  }

  @Test
  public void getKeyWithoutParser_givesLegacyProtoKey() throws Exception {
    PrimitiveSet.Builder builder = PrimitiveSet.newBuilder();
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();
    builder.add(getKeyFromProtoKey(key1), key1);
    PrimitiveSet pset = builder.build();
    com.google.crypto.tink.Key key = pset.getKeysetHandle().getAt(0).getKey();

    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    LegacyProtoKey legacyProtoKey = (LegacyProtoKey) key;
    assertThat(legacyProtoKey.getSerialization(InsecureSecretKeyAccess.get()).getTypeUrl())
        .isEqualTo("typeUrl1");
  }

  @Test
  public void getKeyWithParser_works() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    PrimitiveSet.Builder builder = PrimitiveSet.newBuilder();
    builder.add(getKeyFromProtoKey(protoKey), protoKey);
    PrimitiveSet pset = builder.build();

    com.google.crypto.tink.Key key = pset.getKeysetHandle().getAt(0).getKey();
    assertThat(key).isInstanceOf(HmacKey.class);
    HmacKey hmacKey = (HmacKey) key;
    assertThat(hmacKey.getIdRequirementOrNull()).isEqualTo(42);
  }

  @Test
  public void addPrimitiveWithInvalidKeyThatHasAParser_throws() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    com.google.crypto.tink.proto.HmacKey invalidProtoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(999)
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(0))
            .build();
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createKeyData(
                invalidProtoHmacKey,
                "type.googleapis.com/google.crypto.tink.HmacKey",
                KeyData.KeyMaterialType.SYMMETRIC),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);

    PrimitiveSet.Builder builder = PrimitiveSet.newBuilder();
    assertThrows(
        GeneralSecurityException.class, () -> builder.add(getKeyFromProtoKey(protoKey), protoKey));
  }

  @Test
  public void testDuplicateKeys() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key4 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key5 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key6 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();

    PrimitiveSet pset =
        PrimitiveSet.newBuilder()
            .add(null, key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .add(getKeyFromProtoKey(key4), key4)
            .add(getKeyFromProtoKey(key5), key5)
            .add(getKeyFromProtoKey(key6), key6)
            .build();

    assertThat(pset.getKeysetHandle().size()).isEqualTo(6);
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(0);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(1);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(2);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(2, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(3);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(2, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(4);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(3, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getAt(5);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(3, entry.getId());
    }
    {
      KeysetHandleInterface.Entry entry = pset.getKeysetHandle().getPrimary();
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
  }

  @Test
  public void testAddFullPrimive_withDisabledKey_shouldFail() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> PrimitiveSet.newBuilder().add(getKeyFromProtoKey(key1), key1).build());
    assertThrows(
        GeneralSecurityException.class,
        () -> PrimitiveSet.newBuilder().addPrimary(getKeyFromProtoKey(key1), key1).build());
  }
}
