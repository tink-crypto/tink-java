// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil.AesCmacTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/* Unit tests for Streaming AesCmac computation. */
@RunWith(Theories.class)
public class ChunkedAesCmacTest {
  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  // Test data from https://tools.ietf.org/html/rfc4493#section-4.
  private static final AesCmacTestVector[] cmacTestVectorsFromRfc =
      new AesCmacTestVector[] {
        AesCmacTestUtil.RFC_TEST_VECTOR_0,
        AesCmacTestUtil.RFC_TEST_VECTOR_1,
        AesCmacTestUtil.RFC_TEST_VECTOR_2
      };

  @DataPoints("implementationTestVectors")
  public static final AesCmacTestVector[] cmacImplementationDetailTestVectors =
      new AesCmacTestVector[] {
        AesCmacTestUtil.NOT_OVERFLOWING_INTERNAL_STATE,
        AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE,
        AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE_TWICE,
        AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_ONCE,
        AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_TWICE,
        AesCmacTestUtil.SHORTER_TAG,
        AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_LEGACY,
        AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_TINK,
        AesCmacTestUtil.LONG_KEY_TEST_VECTOR,
      };

  private static final AesCmacTestVector[] cmacVerificationFailFastTestVectors =
      new AesCmacTestVector[] {
        AesCmacTestUtil.WRONG_PREFIX_TAG_LEGACY,
        AesCmacTestUtil.WRONG_PREFIX_TAG_TINK,
        AesCmacTestUtil.TAG_TOO_SHORT
      };

  @DataPoints("parameters")
  public static final AesCmacParameters[] parameters = {
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 11, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 12, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 13, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 14, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 15, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.LEGACY),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 11, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 12, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 13, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 14, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 15, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.TINK),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 11, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 12, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 13, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 14, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 15, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.CRUNCHY),
    AesCmacTestUtil.createAesCmacParameters(32, 10, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 11, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 12, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 13, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 14, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 15, Variant.NO_PREFIX),
    AesCmacTestUtil.createAesCmacParameters(32, 16, Variant.NO_PREFIX),
  };

  @Theory
  public void testCompatibility(@FromDataPoints("parameters") AesCmacParameters parameters)
      throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters)
                    .withFixedId(1234)
                    .makePrimary())
            .build();
    Mac mac = keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    AesCmacKey key = (AesCmacKey) keysetHandle.getAt(0).getKey();
    ChunkedMac chunkedMac = ChunkedAesCmacImpl.create(key);
    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();

    byte[] testData = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
    chunkedMacComputation.update(ByteBuffer.wrap(testData));
    assertThat(mac.computeMac(testData)).isEqualTo(chunkedMacComputation.computeMac());
  }

  @Test
  public void testTagTruncation() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
        macVerification.update(ByteBuffer.wrap(t.message));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }

    // Test with random keys.
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(AesCmacTestUtil.createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = ChunkedAesCmacImpl.create(key);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
        macVerification.update(ByteBuffer.wrap(t.message));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }
  }

  @Test
  public void testBitFlipMessage() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(t.tag);
          macVerification.update(ByteBuffer.wrap(modifiedMessage));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
    // Test with random keys.
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(AesCmacTestUtil.createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = ChunkedAesCmacImpl.create(key);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(t.tag);
          macVerification.update(ByteBuffer.wrap(modifiedMessage));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
  }

  @Test
  public void testBitFlipTag() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
          macVerification.update(ByteBuffer.wrap(t.message));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
    // Test with random keys.
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(AesCmacTestUtil.createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = ChunkedAesCmacImpl.create(key);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
          macVerification.update(ByteBuffer.wrap(t.message));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
  }

  @Test
  public void testThrowExceptionUpdateAfterFinalize() throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    assertThat(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag).isEqualTo(macComputation.computeMac());
    assertThrows(
        IllegalStateException.class,
        () -> macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message)));
    assertThrows(IllegalStateException.class, macComputation::computeMac);

    ChunkedMacVerification macVerification =
        mac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();
    assertThrows(
        IllegalStateException.class,
        () -> macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message)));
    assertThrows(IllegalStateException.class, macVerification::verifyMac);
  }

  @Test
  public void computeAndVerifyMac_withWycheproofVectors_works() throws Exception {
    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors_v1/aes_cmac_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int tagSize = group.get("tagSize").getAsInt();
      int keySize = group.get("keySize").getAsInt();
      if (keySize == 192) {
        // Our implementation does not support 192-bit keys.
        continue;
      }

      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testCase.get("tcId").getAsInt(), testCase.get("comment").getAsString());
        byte[] key = Hex.decode(testCase.get("key").getAsString());
        byte[] msg = Hex.decode(testCase.get("msg").getAsString());
        byte[] tag = Hex.decode(testCase.get("tag").getAsString());
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext and tag.
        // "invalid" are test vectors with invalid parameters or invalid tag.
        // "acceptable" are test vectors with weak parameters or legacy formats, but there are no
        // "acceptable" tests cases for Aes Cmac.
        String result = testCase.get("result").getAsString();
        if (!result.equals("valid") && !result.equals("invalid")) {
          errors.add("FAIL " + tcId + ": result is not valid or invalid");
        }

        try {
          AesCmacParameters noPrefixParameters =
              AesCmacParameters.builder()
                  .setTagSizeBytes(tagSize / 8)
                  .setKeySizeBytes(keySize / 8).build();
          AesCmacKey aesCmacKey =
              AesCmacKey.builder()
                  .setAesKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
                  .setParameters(noPrefixParameters).build();

          ChunkedMac mac = ChunkedAesCmacImpl.create(aesCmacKey);

          ChunkedMacComputation macComputation = mac.createComputation();
          macComputation.update(ByteBuffer.wrap(msg));
          assertThat(macComputation.computeMac()).isEqualTo(tag);

          ChunkedMacVerification macVerification = mac.createVerification(tag);
          macVerification.update(ByteBuffer.wrap(msg));
          macVerification.verifyMac();

          // If the test is "invalid" but no exception is thrown, it's an error.
          if (result.equals("invalid")) {
            errors.add("FAIL " + tcId + ": invalid Wycheproof test did not fail");
          }
        } catch (GeneralSecurityException | AssertionError ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + ": Wycheproof test failed, exception " + ex);
          }
        }
      }
    }
    assertThat(errors).isEmpty();
  }

  @Test
  public void testCreateVerificationFailsFast() throws Exception {
    for (AesCmacTestVector t : cmacVerificationFailFastTestVectors) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);
      assertThrows(GeneralSecurityException.class, () -> mac.createVerification(t.tag));
    }
  }

  /**
   * A cute little table to help verify that the tests below indeed cover the major (when not all)
   * code paths in our streaming AesCmac implementation:
   *
   * <p>-------------------------------------
   * | Inner state | Amount of new data |  # |
   * ----------------------------------------
   * | empty       | empty              |  0 |
   * | empty       | not overflowing    |  1 |
   * | empty       | overflowing        |  2 |
   * | empty       | a lot              |  3 |
   * ----------------------------------------
   * | some data   | empty              |  4 |
   * | some data   | not overflowing    |  5 |
   * | some data   | overflowing        |  6 |
   * | some data   | a lot              |  7 |
   * ----------------------------------------
   * | full        | empty              |  8 |
   * | full        | not overfl. (^)    |  9 |
   * | full        | overflowing        | 10 |
   * | full        | a lot              | 11 |
   * ----------------------------------------
   */

  /* ## 0, 2, 3 */
  @Test
  public void testMacTestVectors() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message));
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message));
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* ## 0, 2, 3 */
  @Test
  public void testMacTestVectorsReadOnlyBuffer() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* ## 1, 2, 3 */
  @Test
  public void testImplementationTestVectors() throws Exception {
    for (AesCmacTestVector t : cmacImplementationDetailTestVectors) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message));
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message));
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* # 0 */
  @Test
  public void testMultipleEmptyUpdates() throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(AesCmacTestUtil.RFC_TEST_VECTOR_0.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    assertThat(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag).isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification =
        mac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();
  }

  /* ## 0, 1, 5, 6, 10  */
  @Test
  public void testSmallUpdates() throws Exception {
    for (AesCmacTestVector t : cmacImplementationDetailTestVectors) {
      ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

      ChunkedMacComputation macComputation = mac.createComputation();
      for (byte b : t.message) {
        byte[] bb = new byte[] {b};
        macComputation.update(ByteBuffer.wrap(bb));
      }
      assertThat(t.tag).isEqualTo(macComputation.computeMac());

      ChunkedMacVerification macVerification = mac.createVerification(t.tag);
      for (byte b : t.message) {
        byte[] bb = new byte[] {b};
        macVerification.update(ByteBuffer.wrap(bb));
      }
      macVerification.verifyMac();
    }
  }

  /* # 8, 9 */
  @Test
  public void testEmptyLastUpdateWithFullStash() throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE.message));
    macComputation.update(ByteBuffer.wrap(new byte[0]));
    assertThat(AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE.tag)
        .isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification =
        mac.createVerification(AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE.tag);
    macVerification.update(ByteBuffer.wrap(AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE.message));
    macVerification.update(ByteBuffer.wrap(new byte[0]));
    macVerification.verifyMac();
  }

  /* ## 1, 4, 5, 6, 7, 8, 9, 11 */
  @Test
  public void testMultipleUpdatesDifferentSizes() throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(AesCmacTestUtil.RFC_TEST_VECTOR_1.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(
        ByteBuffer.wrap(Arrays.copyOf(AesCmacTestUtil.RFC_TEST_VECTOR_1.message, 14)));
    macComputation.update(ByteBuffer.wrap(new byte[0]));
    macComputation.update(
        ByteBuffer.wrap(Arrays.copyOfRange(AesCmacTestUtil.RFC_TEST_VECTOR_1.message, 14, 36)));
    macComputation.update(
        ByteBuffer.wrap(Arrays.copyOfRange(AesCmacTestUtil.RFC_TEST_VECTOR_1.message, 36, 40)));
    assertThat(AesCmacTestUtil.RFC_TEST_VECTOR_1.tag).isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification =
        mac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_1.tag);
    macVerification.update(
        ByteBuffer.wrap(Arrays.copyOf(AesCmacTestUtil.RFC_TEST_VECTOR_1.message, 32)));
    macVerification.update(ByteBuffer.wrap(new byte[0]));
    macVerification.update(
        ByteBuffer.wrap(Arrays.copyOfRange(AesCmacTestUtil.RFC_TEST_VECTOR_1.message, 32, 40)));
    macVerification.verifyMac();

    macComputation = mac.createComputation();
    macComputation.update(
        ByteBuffer.wrap(Arrays.copyOf(AesCmacTestUtil.RFC_TEST_VECTOR_2.message, 16)));
    macComputation.update(
        ByteBuffer.wrap(Arrays.copyOfRange(AesCmacTestUtil.RFC_TEST_VECTOR_2.message, 16, 64)));
    assertThat(AesCmacTestUtil.RFC_TEST_VECTOR_2.tag).isEqualTo(macComputation.computeMac());

    macVerification = mac.createVerification(AesCmacTestUtil.RFC_TEST_VECTOR_2.tag);
    macVerification.update(
        ByteBuffer.wrap(Arrays.copyOf(AesCmacTestUtil.RFC_TEST_VECTOR_2.message, 10)));
    macVerification.update(
        ByteBuffer.wrap(Arrays.copyOfRange(AesCmacTestUtil.RFC_TEST_VECTOR_2.message, 10, 64)));
    macVerification.verifyMac();
  }

  /**
   * Finally, here comes a randomized test. In case, for some reason, the above tests do not catch
   * some bug, we'll have a chance to catch it here.
   */
  @Test
  public void testRandomizedDataChunking() throws Exception {
    for (AesCmacTestVector t : cmacTestVectorsFromRfc) {
      testRandomized(t);
    }
    for (AesCmacTestVector t : cmacImplementationDetailTestVectors) {
      testRandomized(t);
    }

    // Only feed "valid" Wycheproof test cases into the randomized test.
    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors_v1/aes_cmac_test.json");
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int tagSize = group.get("tagSize").getAsInt();
      int keySize = group.get("keySize").getAsInt();
      if (!Arrays.asList(16, 32).contains(keySize / 8)) {
        continue;
      }

      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        if (!testCase.get("result").getAsString().equals("valid")) {
          continue;
        }

        String key = testCase.get("key").getAsString();
        String msg = testCase.get("msg").getAsString();
        String tag = testCase.get("tag").getAsString();

        testRandomized(
            new AesCmacTestVector(
                AesCmacTestUtil.createAesCmacKey(
                    key,
                    AesCmacTestUtil.createAesCmacParameters(
                        keySize / 8, tagSize / 8, Variant.NO_PREFIX),
                    null),
                msg,
                tag));
      }
    }
  }

  private void testRandomized(AesCmacTestVector t) throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);
    ChunkedMacComputation macComputation = mac.createComputation();

    int read = 0;
    StringBuilder debugReadSequence = new StringBuilder();
    debugReadSequence.append(
        "AesCmac tag doesn't match; sequence of update() lengths that lead to the failure: ");

    for (int i = 0; i < 1000000 && read < t.message.length; i++) {
      // The upper bound is exclusive, hence the +1.
      int toRead = Random.randInt(t.message.length - read + 1);

      debugReadSequence.append(toRead);
      if (read + toRead < t.message.length) {
        debugReadSequence.append(", ");
      }

      macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(t.message, read, read + toRead)));
      read += toRead;
    }

    if (read < t.message.length) {
      debugReadSequence.append(t.message.length - read);
      macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(t.message, read, t.message.length)));
    }

    try {
      assertThat(t.tag).isEqualTo(macComputation.computeMac());
    } catch (AssertionError e) {
      throw new AssertionError(debugReadSequence.toString(), e);
    }
  }

  @Theory
  public void testTagModificationAfterCreateVerification(
      @FromDataPoints("implementationTestVectors") AesCmacTestVector t)
      throws Exception {
    ChunkedMac mac = ChunkedAesCmacImpl.create(t.key);

    byte[] mutableTag = Arrays.copyOf(t.tag, t.tag.length);
    ChunkedMacVerification macVerification = mac.createVerification(mutableTag);
    mutableTag[0] ^= (byte) 0x01;
    macVerification.update(ByteBuffer.wrap(t.message));
    macVerification.verifyMac();
  }
}
