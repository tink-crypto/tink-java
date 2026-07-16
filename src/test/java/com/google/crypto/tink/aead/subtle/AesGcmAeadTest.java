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

package com.google.crypto.tink.aead.subtle;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link AesGcmAead}. */
@RunWith(Theories.class)
@LowLevelCryptoCaller
public final class AesGcmAeadTest {

  @BeforeClass
  public static void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test AesGcm in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> AesGcmAead.create(null));
  }

  @Test
  public void testWithAesGcmKey_noPrefix_works() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();

    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();
    Aead aead = AesGcmAead.create(key);
    byte[] ciphertext = aead.encrypt(new byte[] {}, new byte[] {});
    assertThat(ciphertext).hasLength(parameters.getIvSizeBytes() + parameters.getTagSizeBytes());

    assertThat(aead.decrypt(ciphertext, new byte[] {})).isEmpty();

    byte[] fixedCiphertext = Hex.decode("c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");
    assertThat(aead.decrypt(fixedCiphertext, new byte[] {})).isEmpty();
  }

  @Test
  public void testWithAesGcmKey_tinkPrefix_works() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();

    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .setIdRequirement(0x9943243)
            .build();
    Aead aead = AesGcmAead.create(key);
    byte[] ciphertext = aead.encrypt(new byte[] {}, new byte[] {});
    assertThat(ciphertext)
        .hasLength(
            key.getOutputPrefix().size()
                + parameters.getIvSizeBytes()
                + parameters.getTagSizeBytes());
    assertThat(aead.decrypt(ciphertext, new byte[] {})).isEmpty();

    byte[] fixedCiphertext =
        Hex.decode("0109943243c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");
    assertThat(aead.decrypt(fixedCiphertext, new byte[] {})).isEmpty();
  }

  @Test
  public void testWithAesGcmKey_crunchyPrefix_works() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(AesGcmParameters.Variant.CRUNCHY)
            .build();

    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .setIdRequirement(0x9943243)
            .build();
    Aead aead = AesGcmAead.create(key);
    byte[] ciphertext = aead.encrypt(new byte[] {}, new byte[] {});
    assertThat(ciphertext)
        .hasLength(
            key.getOutputPrefix().size()
                + parameters.getIvSizeBytes()
                + parameters.getTagSizeBytes());
    assertThat(aead.decrypt(ciphertext, new byte[] {})).isEmpty();

    byte[] fixedCiphertext =
        Hex.decode("0009943243c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");
    assertThat(aead.decrypt(fixedCiphertext, new byte[] {})).isEmpty();
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors_v1/aes_gcm_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySizeInBits = group.get("keySize").getAsInt();
      assertThat(keySizeInBits).isAnyOf(128, 192, 256);
      JsonArray tests = group.get("tests").getAsJsonArray();
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] iv = Hex.decode(testcase.get("iv").getAsString());
        byte[] keyBytes = Hex.decode(testcase.get("key").getAsString());
        assertThat(keyBytes).hasLength(keySizeInBits / 8);
        AesGcmParameters parameters =
            AesGcmParameters.builder()
                .setKeySizeBytes(keyBytes.length)
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build();
        AesGcmKey key =
            AesGcmKey.builder()
                .setParameters(parameters)
                .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
                .build();
        if (keySizeInBits == 192) {
          // 192-bit keys are not supported. Creating AesGcmAead primitive must fail.
          assertThrows(GeneralSecurityException.class, () -> AesGcmAead.create(key));
          continue;
        }
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        byte[] tag = Hex.decode(testcase.get("tag").getAsString());
        byte[] ciphertext = com.google.crypto.tink.subtle.Bytes.concat(iv, ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        String result = testcase.get("result").getAsString();
        // Tink only supports 12-byte iv.
        if (iv.length != 12) {
          result = "invalid";
        }
        try {
          Aead gcm = AesGcmAead.create(key);
          byte[] decrypted = gcm.decrypt(ciphertext, aad);
          boolean eq = TestUtil.arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            errors.add(
                "FAIL "
                    + tcId
                    + ": accepting invalid ciphertext, cleartext: "
                    + Hex.encode(msg)
                    + ", decrypted: "
                    + Hex.encode(decrypted));
          } else {
            if (!eq) {
              errors.add(
                  "FAIL "
                      + tcId
                      + ": incorrect decryption, result: "
                      + Hex.encode(decrypted)
                      + ", expected: "
                      + Hex.encode(msg));
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + ": cannot decrypt, exception: " + ex);
          }
        }
      }
    }
    assertThat(errors).isEmpty();
  }

  private static byte[] generateAssociatedData() {
    return Random.randBytes(20);
  }

  private static AesGcmParameters[] createValidAesGcmParameters() {
    return exceptionIsBug(
        () ->
            new AesGcmParameters[] {
              AesGcmParameters.builder()
                  .setKeySizeBytes(16)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                  .build(),
              AesGcmParameters.builder()
                  .setKeySizeBytes(16)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build(),
              AesGcmParameters.builder()
                  .setKeySizeBytes(16)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.CRUNCHY)
                  .build(),
              AesGcmParameters.builder()
                  .setKeySizeBytes(32)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                  .build(),
              AesGcmParameters.builder()
                  .setKeySizeBytes(32)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build(),
              AesGcmParameters.builder()
                  .setKeySizeBytes(32)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.CRUNCHY)
                  .build(),
            });
  }

  @DataPoints("validParameters")
  public static final AesGcmParameters[] parameters = createValidAesGcmParameters();

  private static AesGcmKey createRandomKey(AesGcmParameters parameters) throws Exception {
    AesGcmKey.Builder builder =
        AesGcmKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()));
    if (parameters.hasIdRequirement()) {
      builder.setIdRequirement(Random.randInt());
    }
    return builder.build();
  }

  @Theory
  public void ciphertextStartsWithOutputPrefix(
      @FromDataPoints("validParameters") AesGcmParameters parameters) throws Exception {
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      return;
    }
    AesGcmKey key = createRandomKey(parameters);
    Aead aead = AesGcmAead.create(key);

    byte[] ciphertext = aead.encrypt(Random.randBytes(10), generateAssociatedData());

    assertThat(Bytes.copyFrom(ciphertext, 0, key.getOutputPrefix().size()))
        .isEqualTo(key.getOutputPrefix());
  }

  @Theory
  public void encryptThenDecrypt_works(
      @FromDataPoints("validParameters") AesGcmParameters parameters) throws Exception {
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      return;
    }
    AesGcmKey key = createRandomKey(parameters);
    Aead aead = AesGcmAead.create(key);

    byte[] plaintext = Random.randBytes(100);
    byte[] associatedData = generateAssociatedData();

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void computedLength_isAsExpected(
      @FromDataPoints("validParameters") AesGcmParameters parameters) throws Exception {
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      return;
    }
    AesGcmKey key = createRandomKey(parameters);
    Aead aead = AesGcmAead.create(key);

    byte[] plaintext = Random.randBytes(100);
    byte[] associatedData = generateAssociatedData();

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertThat(ciphertext)
        .hasLength(
            key.getOutputPrefix().size()
                + parameters.getIvSizeBytes()
                + plaintext.length
                + parameters.getTagSizeBytes());
  }

  @Test
  public void create_wrongIvSize_throws() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    AesGcmKey key =
        createRandomKey(
            AesGcmParameters.builder()
                .setKeySizeBytes(32)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(GeneralSecurityException.class, () -> AesGcmAead.create(key));
  }

  @Test
  public void create_wrongTagSize_throws() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    AesGcmKey key =
        createRandomKey(
            AesGcmParameters.builder()
                .setKeySizeBytes(32)
                .setIvSizeBytes(12)
                .setTagSizeBytes(12)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
    assertThrows(GeneralSecurityException.class, () -> AesGcmAead.create(key));
  }
}
