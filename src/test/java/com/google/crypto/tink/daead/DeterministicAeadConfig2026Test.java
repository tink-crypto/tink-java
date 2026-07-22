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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link DeterministicAeadConfig2026}. * */
@RunWith(Theories.class)
public class DeterministicAeadConfig2026Test {
  /**
   * A list of Keys which behaves common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>create new keys with the same parameters
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   */
  @DataPoints public static final Key[] keys = createKeys();

  private static Key[] createKeys() {
    try {
      return new Key[] {
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(1234)
            .build(),
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .build(),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Theory
  public void createKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      // Skip this if we are fips only (Theory doesn't allow Assume here).
      return;
    }
    Key createdKey =
        DeterministicAeadConfig2026.get()
            .createKey(key.getParameters(), key.getIdRequirementOrNull());

    assertThat(createdKey.getParameters()).isEqualTo(key.getParameters());
    assertThat(createdKey.getIdRequirementOrNull()).isEqualTo(key.getIdRequirementOrNull());
  }

  @Theory
  public void serializeAndParseKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      // Skip this if we are fips only (Theory doesn't allow Assume here).
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = DeterministicAeadConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      // Skip this if we are fips only (Theory doesn't allow Assume here).
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = DeterministicAeadConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      // Skip this if we are fips only (Theory doesn't allow Assume here).
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    DeterministicAead daead =
        keysetHandle.getPrimitive(DeterministicAeadConfig2026.get(), DeterministicAead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  // The remaining tests are specialized for certain keys only. For example, for DeterministicAead
  // we don't allow GetPrimitive for 32 byte keys (though we still allow creating and
  // parsing/serializing them). We tests these in single tests without @Theory.
  @Test
  public void smallKey_getPrimitive_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Key keyWithSize32 =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1234)
            .build();
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.importKey(keyWithSize32).makePrimary().withFixedId(1234);
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(configuration, DeterministicAead.class));
  }

  @Test
  public void smallKey_parseAndSerializeKey_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Key keyWithSize32 =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1234)
            .build();
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.importKey(keyWithSize32).makePrimary().withFixedId(1234);
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();
    Configuration config = DeterministicAeadConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Test
  public void smallParameters_parseAndSerializeKey_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Parameters parametersWithSize32 =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();

    Configuration config = DeterministicAeadConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parametersWithSize32, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parametersWithSize32);
  }

  @Test
  public void smallKey_createNewKey_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Key createdKey =
        DeterministicAeadConfig2026.get()
            .createKey(
                AesSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build(),
                1234);

    assertThat(createdKey.getParameters())
        .isEqualTo(
            AesSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesSivParameters.Variant.TINK)
                .build());
    assertThat(createdKey.getIdRequirementOrNull()).isEqualTo(1234);
  }

  @Test
  public void getThrowsIfFips() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> DeterministicAeadConfig2026.get());
    }
  }
}

