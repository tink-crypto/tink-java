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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.LegacyProtoParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class RegistryConfigurationTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;

  private static HmacKey rawKey;
  private static KeyData rawKeyData;

  @Before
  public void setUp() throws GeneralSecurityException {
    MacConfig.register();
    createTestKeys();
  }

  private static void createTestKeys() {
    try {
      rawKey =
          HmacKey.builder()
              .setParameters(
                  HmacParameters.builder()
                      .setKeySizeBytes(HMAC_KEY_SIZE)
                      .setTagSizeBytes(HMAC_TAG_SIZE)
                      .setVariant(HmacParameters.Variant.NO_PREFIX)
                      .setHashType(HashType.SHA256)
                      .build())
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();

      // Create the proto key artefacts.
      rawKeyData =
          KeyData.newBuilder()
              .setValue(
                  com.google.crypto.tink.proto.HmacKey.newBuilder()
                      .setParams(
                          HmacParams.newBuilder()
                              .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                              .setTagSize(HMAC_TAG_SIZE)
                              .build())
                      .setKeyValue(
                          ByteString.copyFrom(
                              rawKey.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())))
                      .build()
                      .toByteString())
              .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
              .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
              .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  public void wrap_matchesRegistry() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    KeyManager<Mac> manager =
        KeyManagerRegistry.globalInstance().getKeyManager(rawKeyData.getTypeUrl(), Mac.class);

    Mac registryMac = manager.getPrimitive(rawKeyData.getValue());

    // The following relies on the fact that internally LegacyFullMac uses RegistryConfiguration.
    Mac wrappedConfigurationMac =
        RegistryConfiguration.get()
            .createPrimitive(
                KeysetHandle.newBuilder()
                    .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
                    .build(),
                Mac.class);

    assertThat(wrappedConfigurationMac.computeMac(plaintext))
        .isEqualTo(registryMac.computeMac(plaintext));
  }

  @Test
  public void requestingUnregisteredPrimitives_throws() throws GeneralSecurityException, Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(rawKey.getParameters());
    assertThrows(
        GeneralSecurityException.class,
        () -> RegistryConfiguration.get().createPrimitive(keysetHandle, Aead.class));
  }

  @Test
  public void getUnknown_throws() throws Exception {
    assertThat(RegistryConfiguration.get().getOrNull(Mac.class)).isNull();
  }

  @Test
  public void getProtoKeySerializer_works() throws Exception {
    assertThat(RegistryConfiguration.get().getOrNull(ProtoKeySerializer.class)).isNotNull();
  }

  @Test
  public void getProtoKeySerializer_serializeAndParseKey() throws Exception {
    ProtoKeySerializer serializer = RegistryConfiguration.get().getOrNull(ProtoKeySerializer.class);
    com.google.crypto.tink.ProtoKeySerialization serialization =
        serializer.serializeKey(rawKey, InsecureSecretKeyAccess.get());
    assertThat(serializer.parseKey(serialization, InsecureSecretKeyAccess.get()).equalsKey(rawKey))
        .isTrue();
  }

  @Test
  public void getProtoKeySerializer_serializeAndParseParameters() throws Exception {
    ProtoKeySerializer serializer = RegistryConfiguration.get().getOrNull(ProtoKeySerializer.class);
    ProtoParametersSerialization serializedParameters =
        serializer.serializeParameters(rawKey.getParameters());
    assertThat(serializer.parseParameters(serializedParameters)).isEqualTo(rawKey.getParameters());
  }

  @Test
  public void getProtoKeySerializer_parseKeyWorksWithoutParser() throws Exception {
    com.google.crypto.tink.ProtoKeySerialization serialization =
        com.google.crypto.tink.ProtoKeySerialization.create(
            "unknown_type_url",
            ByteString.EMPTY,
            com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType.SYMMETRIC,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    ProtoKeySerializer serializer = RegistryConfiguration.get().getOrNull(ProtoKeySerializer.class);
    Key key = serializer.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(key).isInstanceOf(LegacyProtoKey.class);
  }

  @Test
  public void getProtoKeySerializer_parseParametersWorksWithoutParser() throws Exception {
    ProtoKeySerializer serializer = RegistryConfiguration.get().getOrNull(ProtoKeySerializer.class);
    Parameters parameters =
        serializer.parseParameters(
            ProtoParametersSerialization.create(
                "UnknownTypeUrl",
                com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.TINK,
                ByteString.EMPTY));
    assertThat(parameters).isInstanceOf(LegacyProtoParameters.class);
  }
}
