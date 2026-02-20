// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.subtle.DeterministicAeads;
import com.google.crypto.tink.mac.internal.AesUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for AesSiv */
@RunWith(Theories.class)
public class AesSivTest {

  private static final int KEY_SIZE_IN_BYTES = 64;

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors/aes_siv_cmac_test.json");
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySizeInBits = group.get("keySize").getAsInt();
      assertThat(keySizeInBits).isAnyOf(256, 384, 512);
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        assertThat(key).hasLength(keySizeInBits / 8);
        if (keySizeInBits == 384) {
          // These key sizes are currently not supported.
          assertThrows(InvalidKeyException.class, () -> new AesSiv(key));
          continue;
        }
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        // Result is one of "valid" and "invalid".
        // "valid" are test vectors with matching plaintext and ciphertext.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext.
        String result = testcase.get("result").getAsString();
        DeterministicAead daead = new AesSiv(key);
        if (result.equals("valid")) {
          byte[] ciphertext = daead.encryptDeterministically(msg, aad);
          assertEquals(tcId, Hex.encode(ct), Hex.encode(ciphertext));
          byte[] plaintext = daead.decryptDeterministically(ct, aad);
          assertEquals(tcId, Hex.encode(msg), Hex.encode(plaintext));
        } else {
          assertThrows(
              String.format("FAIL %s: decrypted invalid ciphertext", tcId),
              GeneralSecurityException.class,
              () -> daead.decryptDeterministically(ct, aad));
        }
      }
    }
  }

  @Test
  public void testWycheproofVectors_createNoPrefix() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    JsonObject json =
        WycheproofTestUtil.readJson("third_party/wycheproof/testvectors/aes_siv_cmac_test.json");
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      int keySizeInBits = group.get("keySize").getAsInt();
      assertThat(keySizeInBits).isAnyOf(256, 384, 512);
      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        byte[] key = Hex.decode(testcase.get("key").getAsString());
        byte[] msg = Hex.decode(testcase.get("msg").getAsString());
        byte[] aad = Hex.decode(testcase.get("aad").getAsString());
        byte[] ct = Hex.decode(testcase.get("ct").getAsString());
        // Result is one of "valid" and "invalid".
        // "valid" are test vectors with matching plaintext and ciphertext.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext.
        String result = testcase.get("result").getAsString();
        assertThat(key).hasLength(keySizeInBits / 8);
        AesSivParameters parameters =
            AesSivParameters.builder()
                .setKeySizeBytes(keySizeInBits / 8)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build();
        SecretBytes keyBytes = SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get());
        AesSivKey aesSivKey =
            AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
        if (keySizeInBits == 384) {
          // These key sizes are currently not supported.
          assertThrows(InvalidKeyException.class, () -> AesSiv.create(aesSivKey));
          continue;
        }
        DeterministicAead daead = AesSiv.create(aesSivKey);
        if (result.equals("valid")) {
          byte[] ciphertext = daead.encryptDeterministically(msg, aad);
          assertEquals(tcId, Hex.encode(ct), Hex.encode(ciphertext));
          byte[] plaintext = daead.decryptDeterministically(ct, aad);
          assertEquals(tcId, Hex.encode(msg), Hex.encode(plaintext));
        } else {
          assertThrows(
              String.format("FAIL %s: decrypted invalid ciphertext", tcId),
              GeneralSecurityException.class,
              () -> daead.decryptDeterministically(ct, aad));
        }
      }
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintext() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = new byte[0];
      byte[] aad = Random.randBytes(Random.randInt(128) + 1);
      byte[] ciphertext = dead.encryptDeterministically(plaintext, aad);
      byte[] rebuiltPlaintext = dead.decryptDeterministically(ciphertext, aad);
      assertThat(ciphertext).hasLength(AesUtil.BLOCK_SIZE);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyAssociatedData() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
      byte[] aad = new byte[0];
      byte[] rebuiltPlaintext =
          dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintextAndEmptyAssociatedData()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = new byte[0];
      byte[] aad = new byte[0];
      byte[] rebuiltPlaintext =
          dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testEncryptDecryptWithNullAssociatedData() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
      byte[] rebuiltPlaintext =
          dead.decryptDeterministically(dead.encryptDeterministically(plaintext, null), null);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testEncryptDecryptWithNullAndEmptyAssociatedDataEquivalent()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
      byte[] emptyAad = new byte[0];
      byte[] emptyAadCiphertext = dead.encryptDeterministically(plaintext, emptyAad);
      byte[] emptyAadRebuiltPlaintext = dead.decryptDeterministically(emptyAadCiphertext, emptyAad);

      byte[] nullAadCipherText = dead.encryptDeterministically(plaintext, null);
      byte[] nullAadRebuiltPlaintext = dead.decryptDeterministically(nullAadCipherText, null);

      assertEquals(Hex.encode(plaintext), Hex.encode(emptyAadRebuiltPlaintext));
      assertEquals(Hex.encode(plaintext), Hex.encode(nullAadRebuiltPlaintext));
      assertEquals(Hex.encode(emptyAadCiphertext), Hex.encode(nullAadCipherText));
    }
  }

  @Test
  public void testEncryptDecryptWithEmptyPlaintextAndNullAssociatedData()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = new byte[0];
      byte[] rebuiltPlaintext =
          dead.decryptDeterministically(dead.encryptDeterministically(plaintext, null), null);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testEncryptDecrypt() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAead dead = new AesSiv(Random.randBytes(KEY_SIZE_IN_BYTES));

    for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
      byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
      byte[] aad = Random.randBytes(Random.randInt(128) + 1);
      byte[] rebuiltPlaintext =
          dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
      assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
    }
  }

  @Test
  public void testModifiedCiphertext() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of ciphertext.
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        assertThrows(
            AEADBadTagException.class, () -> crypter.decryptDeterministically(modified, aad));
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      assertThrows(
          GeneralSecurityException.class, () -> crypter.decryptDeterministically(modified, aad));
    }
  }

  @Test
  public void testModifiedAssociatedData() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of aad.
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        assertThrows(
            AEADBadTagException.class,
            () -> crypter.decryptDeterministically(ciphertext, modified));
      }
    }
  }

  @Test
  public void tooManyAssociatedDatas_throws() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    byte[] plaintext = new byte[127];
    byte[][] ads = new byte[127][127];

    DeterministicAeads crypter = new AesSiv(key);

    assertThrows(
        GeneralSecurityException.class,
        () -> crypter.encryptDeterministicallyWithAssociatedDatas(plaintext, ads));
  }

  @Test
  public void testInvalidKeySizes() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    for (int i = 0; i < 100; i++) {
      final int j = i;
      if (j == 32 || j == 64) {
        continue;
      }

      assertThrows(
          "Keys with invalid size should not be accepted: " + j,
          InvalidKeyException.class,
          () -> new AesSiv(Random.randBytes(j)));
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    byte[] key = Random.randBytes(16);
    assertThrows(GeneralSecurityException.class, () -> new AesSiv(key));
  }

  @Test
  public void testCreate_constructor_singleTest() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    byte[] key =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    DeterministicAead daead = new AesSiv(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  /** Same value as in testCreate_constructor_singleTest. */
  @Test
  public void testCreateForEncryptConstructorForDecrypt_noPrefix() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());
    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    byte[] plaintext = Hex.decode("");
    byte[] aad = Hex.decode("FF");
    byte[] ciphertext = Hex.decode("1BC49C6A894EF5744A0A01D46608CBCC");

    DeterministicAeads daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(plaintext, aad)).isEqualTo(ciphertext);
    assertThat(daead.decryptDeterministically(ciphertext, aad)).isEqualTo(plaintext);

    // also test the DeterministicAeads interface
    assertThat(daead.encryptDeterministicallyWithAssociatedDatas(plaintext, new byte[][] {aad})).isEqualTo(ciphertext);
    assertThat(daead.decryptDeterministicallyWithAssociatedDatas(ciphertext, new byte[][] {aad})).isEqualTo(plaintext);
  }

  @Test
  public void testCreateForEncryptConstructorForDecrypt_tinkPrefix()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    DeterministicAead daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("01445566771BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("01445566771BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void testCreateForEncryptConstructorForDecrypt_crunchyPrefix()
      throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.CRUNCHY)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    DeterministicAead daead = AesSiv.create(key);
    assertThat(daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF")))
        .isEqualTo(Hex.decode("00445566771BC49C6A894EF5744A0A01D46608CBCC"));
    assertThat(
            daead.decryptDeterministically(
                Hex.decode("00445566771BC49C6A894EF5744A0A01D46608CBCC"), Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void keySize32_works() throws GeneralSecurityException {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(32);

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(keyBytes)
            .setIdRequirement(0x44556677)
            .build();
    DeterministicAead daead = AesSiv.create(key);
    byte[] ciphertext = daead.encryptDeterministically(Hex.decode(""), Hex.decode("FF"));
    assertThat(daead.decryptDeterministically(ciphertext, Hex.decode("FF")))
        .isEqualTo(Hex.decode(""));
  }

  @Test
  public void testKeySize48_throws() throws GeneralSecurityException {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(48)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes = SecretBytes.randomBytes(48);

    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThrows(GeneralSecurityException.class, () -> AesSiv.create(key));
  }

  @Test
  public void testCreateThrowsInFipsMode() throws GeneralSecurityException {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build();
    SecretBytes keyBytes =
        SecretBytes.copyFrom(
            Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            InsecureSecretKeyAccess.get());
    AesSivKey key = AesSivKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();
    assertThrows(GeneralSecurityException.class, () -> AesSiv.create(key));
  }

  protected static class TestVector {
    protected byte[] key;
    protected byte[][] aads;
    protected byte[] tag;
    protected byte[] plaintext;
    protected byte[] ciphertext;

    protected TestVector(
        String keyHex, String[] aadsHex, String tagHex, String plaintextHex, String ciphertextHex) {
      this.key = Hex.decode(keyHex);
      this.aads = new byte[aadsHex.length][];
      for (int i = 0; i < aadsHex.length; i++) {
        this.aads[i] = Hex.decode(aadsHex[i]);
      }
      this.plaintext = Hex.decode(plaintextHex);
      // Tink's ciphertext is the concatenation of the tag and the ciphertext.
      this.ciphertext = Hex.decode(tagHex + ciphertextHex);
    }
  }

  // These test vectors are from:
  // https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evpciph_aes_siv.txt
  // it contains the test vectors from https://datatracker.ietf.org/doc/html/rfc5297
  @DataPoints("testCases")
  public static final TestVector[] testVectors = {
    // https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.1
    new TestVector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        new String[] {"101112131415161718191a1b1c1d1e1f2021222324252627"},
        "85632d07c6e8f37f950acd320a2ecc93",
        "112233445566778899aabbccddee",
        "40c02b9690c4dc04daef7f6afe5c"),
    new TestVector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        new String[] {},
        "f1c5fdeac1f15a26779c1501f9fb7588",
        "112233445566778899aabbccddee",
        "27e946c669088ab06da58c5c831c"),
    new TestVector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        new String[] {""},
        "d1022f5b3664e5a4dfaf90f85be6f28a",
        "112233445566778899aabbccddee",
        "b66cff6b8eca0b79f083b39a0901"),
    // https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.2
    new TestVector(
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        new String[] {
          "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
          "102030405060708090a0",
          "09f911029d74e35bd84156c5635688c0"
        },
        "7bdb6e3b432667eb06f4d14bff2fbd0f",
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"),
    new TestVector(
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        new String[] {
          "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
          "",
          "09f911029d74e35bd84156c5635688c0"
        },
        "83ce6593a8fa67eb6fcd2819cedfc011",
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        "30d937b42f71f71f93fc2d8d702d3eac8dc7651eefcd81120081ff29d626f97f3de17f2969b691c91b69b652bf3a6d"),
    new TestVector(
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        new String[] {
          "",
          "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
          "09f911029d74e35bd84156c5635688c0"
        },
        "77dd4a44f5a6b41302121ee7f378de25",
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        "0fcd664c922464c88939d71fad7aefb864e501b0848a07d39201c1067a7288f3dadf0131a823a0bc3d588e8564a5fe"),
    new TestVector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfefffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
        new String[] {"101112131415161718191a1b1c1d1e1f2021222324252627"},
        "724dfb2eaf94dbb19b0ba3a299a0801e",
        "112233445566778899aabbccddee",
        "f3b05a55498ec2552690b89810e4"),
  };

  @Theory
  public void testvector_works(@FromDataPoints("testCases") TestVector test)
      throws GeneralSecurityException {
    if (TinkFips.useOnlyFips()) {
      // We can't run these tests in FIPS mode.
      // And we can't use Assume.assumeFalse here, because that would make all test
      // cases be skipped, and the framework doesn't like that. So we skip the test
      // by returning.
      return;
    }

    AesSiv aesSiv = new AesSiv(test.key);

    assertThat(aesSiv.encryptDeterministicallyWithAssociatedDatas(test.plaintext, test.aads))
        .isEqualTo(test.ciphertext);
    assertThat(aesSiv.decryptDeterministicallyWithAssociatedDatas(test.ciphertext, test.aads))
        .isEqualTo(test.plaintext);
  }
}
