// Copyright 2024 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.XAesGcmKey;
import com.google.crypto.tink.aead.XAesGcmParameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
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

/** Test for XAesGcmSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class XAesGcmProtoSerializationTest {
  private static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.XAesGcmKey";

  private static final int KEY_SIZE_BYTES = 32;
  private static final SecretBytes KEY_BYTES_32 = SecretBytes.randomBytes(KEY_SIZE_BYTES);
  private static final ByteString KEY_BYTES_32_AS_BYTE_STRING =
      ByteString.copyFrom(KEY_BYTES_32.toByteArray(InsecureSecretKeyAccess.get()));

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    XAesGcmProtoSerialization.register(registry);
  }

  @Test
  public void registerTwice() throws Exception {
    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    XAesGcmProtoSerialization.register(registry);
    XAesGcmProtoSerialization.register(registry);
  }

  @Test
  public void serializeParseParameters_noPrefix() throws Exception {
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8);
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.XAesGcmKey",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                        .setSaltSize(parameters.getSaltSizeBytes())
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XAesGcmKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_tink() throws Exception {
    XAesGcmParameters parameters = XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8);

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.XAesGcmKey",
            OutputPrefixType.TINK,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                        .setSaltSize(parameters.getSaltSizeBytes())
                        .build())
                .build());

    ProtoParametersSerialization serialized =
        registry.serializeParameters(parameters, ProtoParametersSerialization.class);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XAesGcmKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseKey_noPrefix() throws Exception {
    XAesGcmKey key =
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 8),
            KEY_BYTES_32,
            /* idRequirement= */ null);

    com.google.crypto.tink.proto.XAesGcmKey protoXAesGcmKey =
        com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
            .setVersion(0)
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .setParams(
                com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                    .setSaltSize(key.getParameters().getSaltSizeBytes())
                    .build())
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XAesGcmKey",
            protoXAesGcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XAesGcmKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void serializeParseKey_tink() throws Exception {
    XAesGcmKey key =
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8),
            KEY_BYTES_32,
            /* idRequirement= */ 123);

    com.google.crypto.tink.proto.XAesGcmKey protoXAesGcmKey =
        com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
            .setVersion(0)
            .setParams(
                com.google.crypto.tink.proto.XAesGcmParams.newBuilder()
                    .setSaltSize(key.getParameters().getSaltSizeBytes())
                    .build())
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .build();

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XAesGcmKey",
            protoXAesGcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    ProtoKeySerialization serialized =
        registry.serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.XAesGcmKey.parser(), serialized, serialization);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(key)).isTrue();
  }

  @Test
  public void testParseKeys_noAccess_throws() throws Exception {
    com.google.crypto.tink.proto.XAesGcmKey protoXAesGcmKey =
        com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
            .setVersion(0)
            .setParams(
                com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
            .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.XAesGcmKey",
            protoXAesGcmKey.toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    assertThrows(GeneralSecurityException.class, () -> registry.parseKey(serialization, null));
  }

  @Test
  public void parseKey_legacy_fails() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.LEGACY,
            1479);
    // Legacy keys aren't supported
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parseKey_crunchy_fails() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.CRUNCHY,
            1479);
    // Crunchy keys aren't supported
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void testSerializeKeys_noAccess_throws() throws Exception {
    XAesGcmKey key =
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 8),
            KEY_BYTES_32,
            /* idRequirement= */ 123);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(key, ProtoKeySerialization.class, null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] INVALID_PARAMETERS_SERIALIZATIONS =
      new ProtoParametersSerialization[] {
        // Unknown output prefix
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(12).build())
                .build()),
        // Bad version
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(12).build())
                .setVersion(1)
                .build()),
        // Bad salt size
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(13).build())
                .setVersion(0)
                .build()),
        ProtoParametersSerialization.create(
            TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.XAesGcmKeyFormat.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(7).build())
                .setVersion(0)
                .build()),
      };

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
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(1)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Unknown prefix
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            1479),
        // Bad Key Length
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(0)
                .setKeyValue(ByteString.copyFrom(new byte[8]))
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(8).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
        // Bad Salt Length
        ProtoKeySerialization.create(
            TYPE_URL,
            com.google.crypto.tink.proto.XAesGcmKey.newBuilder()
                .setVersion(0)
                .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
                .setParams(
                    com.google.crypto.tink.proto.XAesGcmParams.newBuilder().setSaltSize(7).build())
                .build()
                .toByteString(),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.TINK,
            1479),
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
