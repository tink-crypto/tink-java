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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RegistryConfiguration}. */
@RunWith(JUnit4.class)
public class RegistryConfigurationTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;

  private static HmacKey rawKey;
  private static KeyData rawKeyData;
  private static Keyset.Key rawKeysetKey;
  private static LegacyProtoKey legacyProtoRawKey;

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
      KeysetHandle keysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
              .build();
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
      rawKeysetKey =
          Keyset.Key.newBuilder()
              .setKeyData(rawKeyData)
              .setStatus(KeyStatusType.ENABLED)
              .setKeyId(keysetHandle.getPrimary().getId())
              .setOutputPrefixType(OutputPrefixType.RAW)
              .build();
      legacyProtoRawKey =
          new LegacyProtoKey(
              MutableSerializationRegistry.globalInstance()
                  .serializeKey(rawKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
              InsecureSecretKeyAccess.get());
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
            .wrap(
                KeysetHandle.newBuilder()
                    .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
                    .build(),
                MonitoringAnnotations.EMPTY,
                Mac.class);

    assertThat(wrappedConfigurationMac.computeMac(plaintext))
        .isEqualTo(registryMac.computeMac(plaintext));
  }

  @Test
  public void requestingUnregisteredPrimitives_throws() throws GeneralSecurityException {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RegistryConfiguration.get()
                .wrap(
                    KeysetHandle.generateNew(rawKey.getParameters()),
                    MonitoringAnnotations.EMPTY,
                    Aead.class));
  }
}
