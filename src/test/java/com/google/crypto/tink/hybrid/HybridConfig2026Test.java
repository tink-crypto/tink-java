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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.testing.EciesAeadHkdfTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link HybridConfig2026}. */
@RunWith(Theories.class)
public class HybridConfig2026Test {

  private static List<HybridPrivateKey> createKeys() {
    try {
      return Arrays.asList(
          EciesAeadHkdfTestUtil.createTestVector0().getPrivateKey(),
          HpkeTestUtil.createTestVector0().getPrivateKey());
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * A list of Keys which behave common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   * </ul>
   */
  @DataPoints("keys")
  public static final List<HybridPrivateKey> keys = createKeys();

  @Test
  public void get_throwsInFipsMode() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, HybridConfig2026::get);
    }
  }

  @Theory
  public void getPrimitive_encryptDecrypt_works(@FromDataPoints("keys") HybridPrivateKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    KeysetHandle publicKeyHandle = handle.getPublicKeysetHandle();

    HybridDecrypt decrypt = handle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);
    HybridEncrypt encrypt =
        publicKeyHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypt.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypt.decrypt(ciphertext, contextInfo);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Theory
  public void serializeAndParsePrivateKey_works(@FromDataPoints("keys") HybridPrivateKey key)
      throws Exception {
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

    Configuration config = HybridConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParsePublicKey_works(@FromDataPoints("keys") HybridPrivateKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    HybridPublicKey publicKey = key.getPublicKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(publicKey).makePrimary();
    if (publicKey.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(publicKey.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = HybridConfig2026.get();
    byte[] serialized = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, config);
    KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serialized, config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(@FromDataPoints("keys") HybridPrivateKey key)
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = HybridConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void createKey_works(@FromDataPoints("keys") HybridPrivateKey key) throws Exception {
    Configuration config = HybridConfig2026.get();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(key.getParameters())
                    .withFixedId(42)
                    .makePrimary())
            .setConfiguration(config)
            .build();

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Test
  public void getOrNull_unsupportedClass_returnsNull() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    assertThat(HybridConfig2026.get().getOrNull(String.class)).isNull();
  }
}
