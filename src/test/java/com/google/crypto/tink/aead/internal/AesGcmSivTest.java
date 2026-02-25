// Copyright 2017 Google LLC
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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for AesGcmSiv. */
@RunWith(JUnit4.class)
public class AesGcmSivTest {

  private static final Integer[] keySizeInBytes = new Integer[] {16, 32};

  private static Provider conscrypt;

  @BeforeClass
  public static void setUpConscrypt() throws Exception {
    if (TestUtil.isAndroid()) {
      conscrypt = Cipher.getInstance("AES/GCM-SIV/NoPadding").getProvider();
      return;
    }
    // If Conscrypt is not available, we skip all tests.
    Assume.assumeTrue(Conscrypt.isAvailable());
    conscrypt = Conscrypt.newProvider();
  }

  public static Cipher conscryptCipherSupplier() throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM-SIV/NoPadding", conscrypt);
    if (!AesGcmSiv.isAesGcmSivCipher(cipher)) {
      throw new GeneralSecurityException("Cipher is not an AesGcmSiv cipher");
    }
    return cipher;
  }

  public static Aead createFromRawKey(final byte[] key) throws GeneralSecurityException {
    return AesGcmSiv.create(
        AesGcmSivKey.builder()
            .setKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(key.length)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .build(),
        AesGcmSivTest::conscryptCipherSupplier);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    byte[] aad = new byte[] {1, 2, 3};
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      Aead aead = createFromRawKey(key);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        byte[] ciphertext = aead.encrypt(message, aad);
        byte[] decrypted = aead.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
      }
    }
  }

  @Test
  /* BC had a bug, where GCM failed for messages of size > 8192 */
  public void testLongMessages() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      for (int keySize : keySizeInBytes) {
        byte[] key = Random.randBytes(keySize);
        Aead aesGcmSiv = createFromRawKey(key);
        byte[] ciphertext = aesGcmSiv.encrypt(plaintext, aad);
        byte[] decrypted = aesGcmSiv.decrypt(ciphertext, aad);
        assertArrayEquals(plaintext, decrypted);
      }
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    byte[] aad = Random.randBytes(33);
    byte[] key = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    Aead aesGcmSiv = createFromRawKey(key);
    byte[] ciphertext = aesGcmSiv.encrypt(message, aad);

    for (BytesMutation mutation : TestUtil.generateMutations(ciphertext)) {
      assertThrows(
          String.format(
              "Decrypting modified ciphertext should fail : ciphertext = %s, aad = %s,"
                  + " description = %s",
              Hex.encode(mutation.value), Hex.encode(aad), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = aesGcmSiv.decrypt(mutation.value, aad);
          });
    }

    // Modify AAD
    for (BytesMutation mutation : TestUtil.generateMutations(aad)) {
      assertThrows(
          String.format(
              "Decrypting with modified aad should fail: ciphertext = %s, aad = %s,"
                  + " description = %s",
              Arrays.toString(ciphertext), Arrays.toString(mutation.value), mutation.description),
          GeneralSecurityException.class,
          () -> {
            byte[] unused = aesGcmSiv.decrypt(ciphertext, mutation.value);
          });
    }
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors_v1/aes_gcm_siv_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] iv = Hex.decode(testcase.get("iv").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        byte[] tag = Hex.decode(testcase.get("tag").getAsString());
        byte[] ciphertext = Bytes.concat(iv, ct, tag);
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        try {
          Aead aesGcmSiv = createFromRawKey(key);
          byte[] decrypted = aesGcmSiv.decrypt(ciphertext, aad);
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

  @Test
  public void testNullPlaintextOrCiphertext() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    for (int keySize : keySizeInBytes) {
      Aead aesGcmSiv = createFromRawKey(Random.randBytes(keySize));
      byte[] aad = new byte[] {1, 2, 3};
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = aesGcmSiv.encrypt(null, aad);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = aesGcmSiv.encrypt(null, null);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = aesGcmSiv.decrypt(null, aad);
          });
      assertThrows(
          NullPointerException.class,
          () -> {
            byte[] unused = aesGcmSiv.decrypt(null, null);
          });
    }
  }

  @Test
  public void testEmptyAssociatedData() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    byte[] aad = new byte[0];
    for (int keySize : keySizeInBytes) {
      byte[] key = Random.randBytes(keySize);
      Aead aesGcmSiv = createFromRawKey(key);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        { // encrypting with aad as a 0-length array
          byte[] ciphertext = aesGcmSiv.encrypt(message, aad);
          byte[] decrypted = aesGcmSiv.decrypt(ciphertext, aad);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = aesGcmSiv.decrypt(ciphertext, null);
          assertArrayEquals(message, decrypted2);
          byte[] badAad = new byte[] {1, 2, 3};
          assertThrows(
              GeneralSecurityException.class,
              () -> {
                byte[] unused = aesGcmSiv.decrypt(ciphertext, badAad);
              });
        }
        { // encrypting with aad equal to null
          byte[] ciphertext = aesGcmSiv.encrypt(message, null);
          byte[] decrypted = aesGcmSiv.decrypt(ciphertext, aad);
          assertArrayEquals(message, decrypted);
          byte[] decrypted2 = aesGcmSiv.decrypt(ciphertext, null);
          assertArrayEquals(message, decrypted2);
          byte[] badAad = new byte[] {1, 2, 3};
          assertThrows(
              GeneralSecurityException.class,
              () -> {
                byte[] unused = aesGcmSiv.decrypt(ciphertext, badAad);
              });
        }
      }
    }
  }

  @Test
  /*
   * This is a very simple test for the randomness of the nonce. The test simply checks that the
   * multiple ciphertexts of the same message are distinct.
   */
  public void testRandomNonce() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    final int samples = 1 << 17;
    byte[] key = Random.randBytes(16);
    byte[] message = new byte[0];
    byte[] aad = new byte[0];
    Aead aesGcmSiv = createFromRawKey(key);
    HashSet<String> ciphertexts = new HashSet<String>();
    for (int i = 0; i < samples; i++) {
      byte[] ct = aesGcmSiv.encrypt(message, aad);
      String ctHex = Hex.encode(ct);
      assertThat(ciphertexts).doesNotContain(ctHex);
      ciphertexts.add(ctHex);
    }
  }

  @Test
  public void testCreate_encryptAndDecryptFailBeforeAndroid30() throws Exception {
    // On Android API version 29 and older the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeNotNull(apiLevel);
    Assume.assumeTrue(apiLevel < 30);

    // Use an AES GCM test vector from AesGcmJceTest.testWithAesGcmKey_noPrefix_works
    byte[] keyBytes = Hex.decode("5b9604fe14eadba931b0ccf34843dab9");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> AesGcmSiv.create(key, AesGcmSivTest::conscryptCipherSupplier));
  }

  @Test
  public void testWithAesGcmSivKey_noPrefix_works() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    // Test vector draft-irtf-cfrg-gcmsiv-09 in Wycheproof
    byte[] plaintext = Hex.decode("7a806c");
    byte[] associatedData = Hex.decode("46bb91c3c5");
    byte[] keyBytes = Hex.decode("36864200e0eaf5284d884a0e77d31646");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .build();
    Aead aead = AesGcmSiv.create(key, AesGcmSivTest::conscryptCipherSupplier);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext).hasLength(/* length= */ 3 + /* ivSize= */ 12 + /* tagSize= */ 16);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    byte[] fixedCiphertext =
        Hex.decode("bae8e37fc83441b16034566baf60eb711bd85bc1e4d3e0a462e074eea428a8");
    assertThat(aead.decrypt(fixedCiphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void testWithAesGcmSivKey_tinkPrefix_works() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    // Test vector draft-irtf-cfrg-gcmsiv-09 in Wycheproof
    byte[] plaintext = Hex.decode("7a806c");
    byte[] associatedData = Hex.decode("46bb91c3c5");
    byte[] keyBytes = Hex.decode("36864200e0eaf5284d884a0e77d31646");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .setIdRequirement(0x87654321)
            .build();
    Aead aead = AesGcmSiv.create(key, AesGcmSivTest::conscryptCipherSupplier);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext)
        .hasLength(
            5 // prefix
                + 3 // plaintext length
                + 12 // iv size
                + 16 // tag size
            );

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    byte[] fixedCiphertext =
        Hex.decode("0187654321bae8e37fc83441b16034566baf60eb711bd85bc1e4d3e0a462e074eea428a8");
    assertThat(aead.decrypt(fixedCiphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void testWithAesGcmSivKey_crunchyPrefix_works() throws Exception {
    // Skip the test on Android API version 29 and older, because the security provider returns an
    // AES GCM cipher instead of an AES GCM SIV cipher.
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30);

    // Test vector draft-irtf-cfrg-gcmsiv-09 in Wycheproof
    byte[] plaintext = Hex.decode("7a806c");
    byte[] associatedData = Hex.decode("46bb91c3c5");
    byte[] keyBytes = Hex.decode("36864200e0eaf5284d884a0e77d31646");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.CRUNCHY)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .setIdRequirement(0x87654321)
            .build();
    Aead aead = AesGcmSiv.create(key, AesGcmSivTest::conscryptCipherSupplier);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext)
        .hasLength(
            5 // prefix
                + 3 // plaintext length
                + 12 // iv size
                + 16 // tag size
            );

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    byte[] fixedCiphertext =
        Hex.decode("0087654321bae8e37fc83441b16034566baf60eb711bd85bc1e4d3e0a462e074eea428a8");
    assertThat(aead.decrypt(fixedCiphertext, associatedData)).isEqualTo(plaintext);
  }
}
