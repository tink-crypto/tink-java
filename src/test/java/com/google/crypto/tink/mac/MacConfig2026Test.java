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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link MacConfig2026}. */
@RunWith(Theories.class)
public class MacConfig2026Test {
  /**
   * A list of Keys which behave common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>create new keys with the same parameters
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   * </ul>
   */
  @DataPoints public static final Key[] keys = createKeys();

  private static Key[] createKeys() {
    try {
      return new Key[] {
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setTagSizeBytes(16)
                    .setKeySizeBytes(32)
                    .setHashType(HmacParameters.HashType.SHA256)
                    .setVariant(HmacParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1234)
            .build(),
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setTagSizeBytes(16)
                    .setKeySizeBytes(32)
                    .setHashType(HmacParameters.HashType.SHA256)
                    .setVariant(HmacParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build(),
        AesCmacKey.builder()
            .setParameters(
                AesCmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesCmacParameters.Variant.TINK)
                    .build())
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1234)
            .build(),
        AesCmacKey.builder()
            .setParameters(
                AesCmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesCmacParameters.Variant.NO_PREFIX)
                    .build())
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .build(),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Theory
  public void createKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Key createdKey =
        MacConfig2026.get().createKey(key.getParameters(), key.getIdRequirementOrNull());

    assertThat(createdKey.getParameters()).isEqualTo(key.getParameters());
    assertThat(createdKey.getIdRequirementOrNull()).isEqualTo(key.getIdRequirementOrNull());
  }

  @Theory
  public void serializeAndParseKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = MacConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = MacConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_mac_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Mac mac = keysetHandle.getPrimitive(MacConfig2026.get(), Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = mac.computeMac(data);
    mac.verifyMac(tag, data);
  }

  @Theory
  public void getPrimitive_chunkedMac_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    ChunkedMac chunkedMac = keysetHandle.getPrimitive(MacConfig2026.get(), ChunkedMac.class);
    byte[] data = "data".getBytes(UTF_8);
    ChunkedMacComputation computation = chunkedMac.createComputation();
    computation.update(ByteBuffer.wrap(data));
    byte[] tag = computation.computeMac();
    ChunkedMacVerification verification = chunkedMac.createVerification(tag);
    verification.update(ByteBuffer.wrap(data));
    verification.verifyMac();
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForMac() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(config, Mac.class));
  }

  @Test
  public void config_disallowsNon32ByteAesCmacKeyForChunkedMac() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(10)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(parameters)
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(config, ChunkedMac.class));
  }

  @Test
  public void createKey_unrecognizedParameters_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    Configuration config = MacConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  private static interface DummyPrimitive {}

  @Test
  public void createPrimitive_unsupportedPrimitiveClass_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HmacParameters parameters =
        HmacParameters.builder()
            .setTagSizeBytes(16)
            .setKeySizeBytes(32)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.NO_PREFIX)
            .build();
    HmacKey key =
        HmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(config, DummyPrimitive.class));
  }

  @Test
  public void createKey_aesCmacParametersWithIdRequirementButPassedNull_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.TINK)
            .build();
    Configuration config = MacConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  @Test
  public void createKey_hmacParametersWithIdRequirementButPassedNull_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HmacParameters parameters =
        HmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setHashType(HmacParameters.HashType.SHA256)
            .setVariant(HmacParameters.Variant.TINK)
            .build();
    Configuration config = MacConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  @Test
  public void get_throwsInFipsMode() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, MacConfig2026::get);
    }
  }
}
