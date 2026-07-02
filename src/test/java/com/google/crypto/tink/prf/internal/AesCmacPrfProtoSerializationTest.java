// Copyright 2023 Google LLC
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

package com.google.crypto.tink.prf.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.prf.AesCmacPrfKey;
import com.google.crypto.tink.prf.AesCmacPrfParameters;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class AesCmacPrfProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

  private static final SecretBytes KEY_BYTES_16 = SecretBytes.randomBytes(16);
  private static final ByteString KEY_BYTES_16_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_16.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @BeforeClass
  public static void setUp() throws Exception {
    AesCmacPrfProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    AesCmacPrfProtoSerialization.register(registry);
    AesCmacPrfProtoSerialization.register(registry);
  }

  @Test
  public void register_serializationRegistryBuilderParameters() throws Exception {
    com.google.crypto.tink.internal.SerializationRegistry.Builder builder =
        new com.google.crypto.tink.internal.SerializationRegistry.Builder();
    AesCmacPrfProtoSerialization.register(builder);
    com.google.crypto.tink.internal.SerializationRegistry serializationRegistry = builder.build();

    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(32);
    ProtoParametersSerialization serializedParams =
        serializationRegistry.serializeParameters(parameters);
    assertThat(serializationRegistry.parseParameters(serializedParams)).isEqualTo(parameters);
  }

  @Test
  public void register_serializationRegistryBuilderKeys() throws Exception {
    com.google.crypto.tink.internal.SerializationRegistry.Builder builder =
        new com.google.crypto.tink.internal.SerializationRegistry.Builder();
    AesCmacPrfProtoSerialization.register(builder);
    com.google.crypto.tink.internal.SerializationRegistry serializationRegistry = builder.build();

    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32));
    ProtoKeySerialization serializedKey =
        serializationRegistry.serializeKey(key, InsecureSecretKeyAccess.get());
    assertThat(
            serializationRegistry
                .parseKey(serializedKey, InsecureSecretKeyAccess.get())
                .equalsKey(key))
        .isTrue();
  }

  @Theory
  public void serializeAndParseParameters(@FromDataPoints("keySizes") int keySize)
      throws Exception {
    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(keySize);

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCmacPrfKeyFormat.newBuilder()
                .setKeySize(keySize)
                .build()
                .toByteString());

    ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCmacPrfKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeAndParseKey(@FromDataPoints("keySizes") int keySize) throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(keySize);
    AesCmacPrfKey key = AesCmacPrfKey.create(AesCmacPrfParameters.create(keySize), keyBytes);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(
                    ByteString.copyFrom(keyBytes.toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized = registry.serializeKey(key, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.AesCmacPrfKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testSerializeKey_noAccess_fails() throws Exception {
    AesCmacPrfKey key = AesCmacPrfKey.create(AesCmacPrfParameters.create(16), KEY_BYTES_16);

    assertThrows(GeneralSecurityException.class, () -> registry.serializeKey(key, null));
  }

  @Test
  public void testParseKey_noAccess_fails() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  private static ProtoParametersSerialization[] createInvalidParameters() {
    try {
      return new ProtoParametersSerialization[] {
        // Invalid type URL.
        ProtoParametersSerialization.create(
            "i.am.a.random.type.url",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .build()
                .toByteString()),

        // Invalid output prefix type.
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.AesCmacPrfKeyFormat.newBuilder()
                .setKeySize(16)
                .build()
                .toByteString()),

        // Invalid key size.
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.AesCmacPrfKeyFormat.newBuilder()
                .setKeySize(12)
                .build()
                .toByteString()),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] invalidParametersSerializations =
      createInvalidParameters();

  @Theory
  public void testParseInvalidParameters_fails(
      @FromDataPoints("invalidParametersSerializations")
          ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  private static ProtoKeySerialization[] createInvalidKeySerializations() {
    try {
      return new ProtoKeySerialization[] {
        // Invalid type URL.
        ProtoKeySerialization.create(
            "i.am.a.random.type.url",
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid version.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(1)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid key size.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(ByteString.copyFrom(new byte[12]))
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid proto encoding.
        ProtoKeySerialization.create(
            TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null),
        // Invalid output prefix type.
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.AesCmacPrfKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_16_AS_BYTE_STRING)
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            123),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidKeySerializations")
  public static final ProtoKeySerialization[] INVALID_KEY_SERIALIZATIONS =
      createInvalidKeySerializations();

  @Theory
  public void testParseInvalidKeys_throws(
      @FromDataPoints("invalidKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
