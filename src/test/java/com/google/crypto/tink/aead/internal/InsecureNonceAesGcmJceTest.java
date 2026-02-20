// Copyright 2021 Google LLC
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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link InsecureNonceAesGcmJce}. */
@RunWith(JUnit4.class)
public class InsecureNonceAesGcmJceTest {

  private static Integer[] keySizeInBytes;

  @BeforeClass
  public static void setUp() throws Exception {
    keySizeInBytes = new Integer[] {16, 32};
  }

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
  public void testEncryptDecrypt() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] associatedData = Random.randBytes(20);
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
        byte[] ciphertext = gcm.encrypt(iv, message, associatedData);
        byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
        assertArrayEquals(message, decrypted);
      }
    }
  }

  @Test
  public void encryptDecryptWithCiphertextOffsets() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] key = Random.randBytes(32);
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    byte[] message = Random.randBytes(42);
    byte[] associatedData = Random.randBytes(20);

    int ciphertextOffset = 17;

    byte[] ciphertextWithOffset = gcm.encrypt(iv, message, ciphertextOffset, associatedData);

    // ciphertext should start at offset ciphertextSize=17 in ciphertextWithOffset.
    byte[] ciphertext =
        Arrays.copyOfRange(ciphertextWithOffset, ciphertextOffset, ciphertextWithOffset.length);
    byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(message);

    byte[] decrypted2 = gcm.decrypt(iv, ciphertextWithOffset, ciphertextOffset, associatedData);
    assertThat(decrypted2).isEqualTo(message);
  }

  @Test
  public void ciphertext_lengthIsMessageSizePlusTagSize() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    byte[] key = Random.randBytes(32);
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);

    byte[] message = Random.randBytes(42);
    byte[] associatedData = Random.randBytes(13);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    byte[] ciphertext = gcm.encrypt(iv, message, associatedData);
    assertThat(ciphertext).hasLength(message.length + InsecureNonceAesGcmJce.TAG_SIZE_IN_BYTES);
  }

  /** BC had a bug, where GCM failed for messages of size > 8192 */
  @Test
  public void testLongMessages() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    Assume.assumeFalse(TestUtil.isAndroid()); // doesn't work on Android

    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] associatedData = Random.randBytes(dataSize / 3);
      for (int keySize : keySizeInBytes) {
        byte[] key = Random.randBytes(keySize);
        InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
        byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
        byte[] ciphertext = gcm.encrypt(iv, plaintext, associatedData);
        byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
        assertArrayEquals(plaintext, decrypted);
      }
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] associatedData = Random.randBytes(20);
    byte[] key = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    byte[] ciphertext = gcm.encrypt(iv, message, associatedData);

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          String.format(
              "Decrypting modified ciphertext should fail : ciphertext = %s, associatedData = %s,"
                  + " description = %s",
              Hex.encode(mutation.value), Hex.encode(associatedData), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, mutation.value, associatedData);
          });
    }

    // Modify AAD
    if (associatedData != null && associatedData.length != 0) {
      for (BytesMutation mutation : TestUtil.generateMutations(associatedData)) {
        assertThrows(
            String.format(
                "Decrypting with modified associatedData should fail: ciphertext = %s,"
                    + " associatedData = %s, description = %s",
                Arrays.toString(ciphertext), Arrays.toString(mutation.value), mutation.description),
            GeneralSecurityException.class,
            () -> {
              byte[] unused = gcm.decrypt(iv, ciphertext, mutation.value);
            });
      }
    }
  }

  @Test
  public void testTruncatedCiphertext() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] associatedData = Random.randBytes(20);
    byte[] key = Random.randBytes(16);
    byte[] message = new byte[0];
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);

    byte[] ciphertext = gcm.encrypt(iv, message, associatedData);
    byte[] truncatedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length - 1);

    assertThrows(
        GeneralSecurityException.class, () -> gcm.decrypt(iv, truncatedCiphertext, associatedData));
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors/aes_gcm_test.json");
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
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] iv = Hex.decode(testcase.get("iv").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        assertThat(key).hasLength(keySizeInBits / 8);
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] associatedData = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        byte[] tag = Hex.decode(testcase.get("tag").getAsString());
        byte[] ciphertext = Bytes.concat(ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();
        // Tink only supports 12-byte iv.
        if (iv.length != 12) {
          result = "invalid";
        }
        if (keySizeInBits == 192) {
          // This key size is currently not supported.
          assertThrows(GeneralSecurityException.class, () -> new InsecureNonceAesGcmJce(key));
          continue;
        }
        try {
          InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
          // Encryption.
          byte[] encrypted = gcm.encrypt(iv, msg, associatedData);
          boolean ciphertextMatches = TestUtil.arrayEquals(encrypted, ciphertext);
          if (result.equals("valid") && !ciphertextMatches) {
            errors.add(
                "FAIL "
                    + tcId
                    + ": incorrect encryption, result: "
                    + Hex.encode(encrypted)
                    + ", expected: "
                    + Hex.encode(ciphertext));
          }
          // Decryption.
          byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
          boolean plaintextMatches = TestUtil.arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            errors.add(
                "FAIL "
                    + tcId
                    + ": accepting invalid ciphertext, cleartext: "
                    + Hex.encode(msg)
                    + ", decrypted: "
                    + Hex.encode(decrypted));
          } else {
            if (!plaintextMatches) {
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

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    for (int keySize : keySizeInBytes) {
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(Random.randBytes(keySize));
      byte[] associatedData = Random.randBytes(20);
      byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.encrypt(iv, null, associatedData);
          });
      byte[] iv2 = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.encrypt(iv2, null, null);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, null, associatedData);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = gcm.decrypt(iv, null, null);
          });
    }
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    byte[] associatedData = new byte[0];
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        { // encrypting with associatedData as a 0-length array
          byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
          byte[] ciphertext = gcm.encrypt(iv, message, associatedData);
          byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = gcm.decrypt(iv, ciphertext, null);
          assertArrayEquals(message, decrypted2);
          byte[] badAad = new byte[] {1, 2, 3};
          assertThrows(
              GeneralSecurityException.class,
              () -> gcm.decrypt(iv, ciphertext, badAad));
        }
        { // encrypting with associatedData equal to null
          byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
          byte[] ciphertext = gcm.encrypt(iv, message, null);
          byte[] decrypted = gcm.decrypt(iv, ciphertext, associatedData);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = gcm.decrypt(iv, ciphertext, null);
          assertArrayEquals(message, decrypted2);
          byte[] badAad = new byte[] {1, 2, 3};
          assertThrows(
              GeneralSecurityException.class,
              () -> gcm.decrypt(iv, ciphertext, badAad));
        }
      }
    }
  }

  /**
   * This is a very simple test for the randomness of the nonce. The test simply checks that the
   * multiple ciphertexts of the same message are distinct.
   */
  @Test
  public void testRandomNonce() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    final int samples = 1 << 17;
    byte[] key = Random.randBytes(16);
    byte[] message = new byte[0];
    byte[] associatedData = Random.randBytes(20);
    InsecureNonceAesGcmJce gcm = new InsecureNonceAesGcmJce(key);
    HashSet<String> ciphertexts = new HashSet<>();
    for (int i = 0; i < samples; i++) {
      byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      byte[] ct = gcm.encrypt(iv, message, associatedData);
      String ctHex = Hex.encode(ct);
      assertThat(ciphertexts).doesNotContain(ctHex);
      ciphertexts.add(ctHex);
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    byte[] key = Random.randBytes(16);
    assertThrows(GeneralSecurityException.class, () -> new InsecureNonceAesGcmJce(key));
  }
}
