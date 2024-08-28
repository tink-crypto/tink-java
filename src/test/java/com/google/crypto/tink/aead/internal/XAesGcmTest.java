// Copyright 2024 Google LLC
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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XAesGcmKey;
import com.google.crypto.tink.aead.XAesGcmParameters;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class XAesGcmTest {

  private static final SecretBytes SECRET_BYTES = SecretBytes.randomBytes(32);
  private static final byte[] plaintext = "plaintext".getBytes(UTF_8);
  private static final byte[] associatedData = "associatedData".getBytes(UTF_8);
  private static final int IV_SIZE_IN_BYTES = AesGcmJceUtil.IV_SIZE_IN_BYTES;
  private static final int TAG_SIZE_IN_BYTES = AesGcmJceUtil.TAG_SIZE_IN_BYTES;
  private static final int SALT_SIZE_IN_BYTES = 8;
  private static final int KEY_ID = 5572613;

  XAesGcmKey createKey(XAesGcmParameters.Variant variant, int saltSize)
      throws GeneralSecurityException {
    return XAesGcmKey.create(XAesGcmParameters.create(variant, saltSize), SECRET_BYTES, null);
  }

  @Test
  public void createPrimitive() throws Exception {
    assertNotNull(
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES)));
  }

  @Test
  public void encryptNullPlaintext_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    assertThrows(NullPointerException.class, () -> xAesGcm.encrypt(null, associatedData));
  }

  @Test
  public void decryptNullCiphertext_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    assertThrows(NullPointerException.class, () -> xAesGcm.decrypt(null, associatedData));
  }

  @Test
  public void encryptDecrypt() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    byte[] decrypted = xAesGcm.decrypt(ciphertext, associatedData);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void encryptDecrypt_withTinkVariant() throws Exception {
    byte[] outputPrefix = OutputPrefixUtil.getTinkOutputPrefix(KEY_ID).toByteArray();
    Aead xAesGcm =
        XAesGcm.create(
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, SALT_SIZE_IN_BYTES),
                SECRET_BYTES,
                KEY_ID));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);

    assertThat(Arrays.copyOfRange(ciphertext, 0, outputPrefix.length)).isEqualTo(outputPrefix);
  }

  @Test
  public void encryptDecrypt_withTinkVariant_differentOutputPrefix_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, SALT_SIZE_IN_BYTES),
                SECRET_BYTES,
                KEY_ID));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    byte[] outputPrefix = OutputPrefixUtil.getTinkOutputPrefix(111111).toByteArray();
    System.arraycopy(outputPrefix, 0, ciphertext, 0, outputPrefix.length);

    assertThrows(GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, associatedData));
  }

  @Test
  public void encryptDecrypt_withCrunchyVariant() throws Exception {
    byte[] outputPrefix = OutputPrefixUtil.getLegacyOutputPrefix(KEY_ID).toByteArray();
    Aead xAesGcm =
        XAesGcm.create(
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, SALT_SIZE_IN_BYTES),
                SECRET_BYTES,
                KEY_ID));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);

    assertThat(Arrays.copyOfRange(ciphertext, 0, outputPrefix.length)).isEqualTo(outputPrefix);
  }

  @Test
  public void encryptDecrypt_withCrunchyVariant_differentOutputPrefix_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.CRUNCHY, SALT_SIZE_IN_BYTES),
                SECRET_BYTES,
                KEY_ID));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    byte[] outputPrefix = OutputPrefixUtil.getLegacyOutputPrefix(11111).toByteArray();
    System.arraycopy(outputPrefix, 0, ciphertext, 0, outputPrefix.length);

    assertThrows(GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, associatedData));
  }

  @Test
  public void encryptDecrypt_withoutAadFails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);

    assertThrows(
        GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, "".getBytes(UTF_8)));
  }

  @Test
  public void decrypt_withModifiedSalt_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    ciphertext[0]++;
    assertThrows(GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, associatedData));
  }

  @Test
  public void decrypt_withModifiedIv_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    ciphertext[SALT_SIZE_IN_BYTES + 2]++;
    assertThrows(GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, associatedData));
  }

  @Test
  public void decrypt_withModifiedTag_fails() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    ciphertext[SALT_SIZE_IN_BYTES + IV_SIZE_IN_BYTES + 1]++;
    assertThrows(GeneralSecurityException.class, () -> xAesGcm.decrypt(ciphertext, associatedData));
  }

  @Test
  public void encryptGeneratesNewSaltAndIv() throws Exception {
    Aead xAesGcm =
        XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, SALT_SIZE_IN_BYTES));

    byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
    byte[] ciphertext2 = xAesGcm.encrypt(plaintext, associatedData);

    byte[] salt1 = Arrays.copyOfRange(ciphertext, 0, SALT_SIZE_IN_BYTES);
    byte[] salt2 = Arrays.copyOfRange(ciphertext2, 0, SALT_SIZE_IN_BYTES);
    byte[] iv1 =
        Arrays.copyOfRange(ciphertext, SALT_SIZE_IN_BYTES, SALT_SIZE_IN_BYTES + IV_SIZE_IN_BYTES);
    byte[] iv2 =
        Arrays.copyOfRange(ciphertext2, SALT_SIZE_IN_BYTES, SALT_SIZE_IN_BYTES + IV_SIZE_IN_BYTES);
    assertThat(salt1).isNotEqualTo(salt2);
    assertThat(iv1).isNotEqualTo(iv2);
  }

  @Test
  public void encryptGeneratesValidSaltSize() throws Exception {
    for (int saltSize = 8; saltSize <= 12; saltSize++) {
      Aead xAesGcm = XAesGcm.create(createKey(XAesGcmParameters.Variant.NO_PREFIX, saltSize));
      byte[] ciphertext = xAesGcm.encrypt(plaintext, associatedData);
      byte[] decrypted = xAesGcm.decrypt(ciphertext, associatedData);

      assertThat(ciphertext)
          .hasLength(saltSize + IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES);
      assertThat(decrypted).isEqualTo(plaintext);
    }
  }

  public static class XAesGcmTestVector {
    public String hexKey;
    public int saltSize;
    public String plaintext;
    public String associatedData;
    public String nonce;
    public String hexCiphertext;

    public byte[] key() {
      return Hex.decode(hexKey);
    }

    public byte[] ciphertext() {
      return Hex.decode(hexCiphertext);
    }

    public XAesGcmTestVector(
        String hexKey,
        int saltSize,
        String plaintext,
        String associatedData,
        String nonce,
        String hexCiphertext) {
      this.hexKey = hexKey;
      this.saltSize = saltSize;
      this.plaintext = plaintext;
      this.associatedData = associatedData;
      this.nonce = nonce;
      this.hexCiphertext = hexCiphertext;
    }

  }

  // Test vectors from:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md#test-vectors.
  @DataPoints("test_vectors")
  public static final XAesGcmTestVector[] TEST_VECTORS =
      new XAesGcmTestVector[] {
        new XAesGcmTestVector(
            /* hexKey= */ "0101010101010101010101010101010101010101010101010101010101010101",
            /* saltSize= */ 12,
            /* plaintext= */ "XAES-256-GCM",
            /* associatedData= */ "",
            /* nonce= */ "ABCDEFGHIJKLMNOPQRSTUVWX",
            /* hexCiphertext= */ "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
        new XAesGcmTestVector(
            /* hexKey= */ "0303030303030303030303030303030303030303030303030303030303030303",
            /* saltSize= */ 12,
            /* plaintext= */ "XAES-256-GCM",
            /* associatedData= */ "c2sp.org/XAES-256-GCM",
            /* nonce= */ "ABCDEFGHIJKLMNOPQRSTUVWX",
            /* hexCiphertext= */ "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"),
      };

  @Theory
  public void decryptTestVectors(@FromDataPoints("test_vectors") XAesGcmTestVector testVector)
      throws Exception {
    Aead xAesGcm =
        XAesGcm.create(
            XAesGcmKey.create(
                XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, testVector.saltSize),
                SecretBytes.copyFrom(testVector.key(), InsecureSecretKeyAccess.get()),
                null));
    byte[] nonce = testVector.nonce.getBytes(UTF_8);
    byte[] ciphertext = new byte[testVector.ciphertext().length + nonce.length];
    System.arraycopy(nonce, 0, ciphertext, 0, nonce.length);
    System.arraycopy(
        testVector.ciphertext(), 0, ciphertext, nonce.length, testVector.ciphertext().length);

    byte[] decrypted = xAesGcm.decrypt(ciphertext, testVector.associatedData.getBytes(UTF_8));

    assertArrayEquals(testVector.plaintext.getBytes(UTF_8), decrypted);
  }
}
