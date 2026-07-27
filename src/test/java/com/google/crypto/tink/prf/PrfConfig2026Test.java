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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link PrfConfig2026}. */
@RunWith(Theories.class)
public class PrfConfig2026Test {
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
        HmacPrfKey.builder()
            .setParameters(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HmacPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build(),
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build(),
        AesCmacPrfKey.create(AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32)),
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
        PrfConfig2026.get().createKey(key.getParameters(), key.getIdRequirementOrNull());

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

    Configuration config = PrfConfig2026.get();
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
    Configuration config = PrfConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_works(Key key) throws Exception {
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

    PrfSet prfSet = keysetHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class);
    byte[] message = "message".getBytes(UTF_8);
    byte[] output = prfSet.computePrimary(message, 16);
    assertThat(output).hasLength(16);
  }

  @Test
  public void createKey_withNonNullIdRequirement_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    Configuration config = PrfConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, 1234));
  }

  @Test
  public void wrongAesCmacPrfKeySize_getPrimitive_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    AesCmacPrfKey key =
        AesCmacPrfKey.create(AesCmacPrfParameters.create(16), SecretBytes.randomBytes(16));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(PrfConfig2026.get(), PrfSet.class));
  }

  @Test
  public void wrongHkdfPrfKeySize_getPrimitive_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(16)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = PrfConfig2026.get();
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(config, PrfSet.class));
  }

  @Test
  public void wrongHkdfPrfHashFunction_getPrimitive_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA1)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration configuration = PrfConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(configuration, PrfSet.class));
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
    Configuration config = PrfConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }

  private static interface DummyPrimitive {}

  @Test
  public void createPrimitive_unsupportedPrimitiveClass_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfKey key =
        HmacPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Configuration config = PrfConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(config, DummyPrimitive.class));
  }

  @Test
  public void get_throwsInFipsMode() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, PrfConfig2026::get);
    }
  }
}
