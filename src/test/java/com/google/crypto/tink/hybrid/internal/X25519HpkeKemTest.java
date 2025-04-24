// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.internal.testing.TestFiles;
import com.google.crypto.tink.testing.HpkeTestId;
import com.google.crypto.tink.testing.HpkeTestSetup;
import com.google.crypto.tink.testing.HpkeTestUtil;
import com.google.crypto.tink.testing.HpkeTestVector;
import com.google.crypto.tink.util.Bytes;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link X25519HpkeKem}. */
@RunWith(JUnit4.class)
public final class X25519HpkeKemTest {
  private static final byte[] exportOnlyAeadId = HpkeUtil.intToByteArray(2, 0xffff);
  private static final String MAC_ALGORITHM = "HmacSha256";

  private static Map<HpkeTestId, HpkeTestVector> testVectors;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpTestVectors() throws IOException {
    String path = "testdata/testvectors/hpke_boringssl.json";
    testVectors =
        HpkeTestUtil.parseTestVectors(new InputStreamReader(TestFiles.openInputFile(path), UTF_8));
  }

  private HpkeTestId getDefaultTestId(byte[] mode) {
    return new HpkeTestId(
        mode,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  static HpkeKemPrivateKey toHpkeKemPrivateKey(byte[] privateKeyBytes, byte[] publicKeyBytes) {
    return new HpkeKemPrivateKey(Bytes.copyFrom(privateKeyBytes), Bytes.copyFrom(publicKeyBytes));
  }

  private void encapsulate(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();

    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeKemEncapOutput result;
    if (mode == HpkeUtil.BASE_MODE) {
      result =
          kem.encapsulateWithFixedEphemeralKey(
              testSetup.recipientPublicKey,
              testSetup.senderEphemeralPrivateKey,
              testSetup.senderEphemeralPublicKey);
    } else if (mode == HpkeUtil.AUTH_MODE) {
      result =
          kem.authEncapsulateWithFixedEphemeralKey(
              testSetup.recipientPublicKey,
              testSetup.senderEphemeralPrivateKey,
              testSetup.senderEphemeralPublicKey,
              toHpkeKemPrivateKey(testSetup.senderPrivateKey, testSetup.senderPublicKey));
    } else {
      throw new IllegalArgumentException("Unsupported mode: " + mode[0]);
    }
    expect.that(result.getSharedSecret()).isEqualTo(testSetup.sharedSecret);
    expect.that(result.getEncapsulatedKey()).isEqualTo(testSetup.encapsulatedKey);
  }

  private void decapsulate(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    HpkeTestId testId = new HpkeTestId(mode, kemId, kdfId, aeadId);
    HpkeTestSetup testSetup = testVectors.get(testId).getTestSetup();

    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    byte[] result;
    if (mode == HpkeUtil.BASE_MODE) {
      result =
          kem.decapsulate(
              testSetup.encapsulatedKey,
              toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey));
    } else if (mode == HpkeUtil.AUTH_MODE) {
      result =
          kem.authDecapsulate(
              testSetup.encapsulatedKey,
              toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey),
              testSetup.senderPublicKey);
    } else {
      throw new IllegalArgumentException("Unsupported mode: " + mode[0]);
    }
    expect.that(result).isEqualTo(testSetup.sharedSecret);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void authEncapsulate_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256Aes256Gcm() throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void authEncapsulate_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ChaCha20Poly1305()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void authEncapsulate_succeedsWithX25519HkdfSha256ChaCha20Poly1305()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void encapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        exportOnlyAeadId);
  }

  @Test
  public void authEncapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    encapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        exportOnlyAeadId);
  }

  @Test
  public void encapsulate_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.BASE_MODE)).getTestSetup();
    byte[] validRecipientPublicKey = testSetup.recipientPublicKey;
    assertThrows(NoSuchAlgorithmException.class, () -> kem.encapsulate(validRecipientPublicKey));
  }

  @Test
  public void authEncapsulate_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.AUTH_MODE)).getTestSetup();
    byte[] validRecipientPublicKey = testSetup.recipientPublicKey;
    HpkeKemPrivateKey hpkeKemPrivateKey =
        toHpkeKemPrivateKey(testSetup.senderPrivateKey, testSetup.recipientPublicKey);
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kem.authEncapsulate(validRecipientPublicKey, hpkeKemPrivateKey));
  }

  @Test
  public void encapsulate_failsWithInvalidRecipientPublicKey() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.BASE_MODE)).getTestSetup();
    byte[] invalidRecipientPublicKey =
        Arrays.copyOf(testSetup.recipientPublicKey, testSetup.recipientPublicKey.length + 2);
    assertThrows(InvalidKeyException.class, () -> kem.encapsulate(invalidRecipientPublicKey));
  }

  @Test
  public void authEncapsulate_failsWithInvalidRecipientPublicKey() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.AUTH_MODE)).getTestSetup();
    byte[] invalidRecipientPublicKey =
        Arrays.copyOf(testSetup.recipientPublicKey, testSetup.recipientPublicKey.length + 2);
    HpkeKemPrivateKey hpkeKemPrivateKey =
        toHpkeKemPrivateKey(testSetup.senderPrivateKey, testSetup.senderPublicKey);
    assertThrows(
        InvalidKeyException.class,
        () -> kem.authEncapsulate(invalidRecipientPublicKey, hpkeKemPrivateKey));
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256Aes128Gcm() throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void authDecapsulate_succeedsWithX25519HkdfSha256Aes128Gcm()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_128_GCM_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256Aes256Gcm() throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void authDecapsulate_succeedsWithX25519HkdfSha256Aes256Gcm()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.AES_256_GCM_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ChaCha20Poly1305()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void authDecapsulate_succeedsWithX25519HkdfSha256ChaCha20Poly1305()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        HpkeUtil.CHACHA20_POLY1305_AEAD_ID);
  }

  @Test
  public void decapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.BASE_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        exportOnlyAeadId);
  }

  @Test
  public void authDecapsulate_succeedsWithX25519HkdfSha256ExportOnlyAead()
      throws GeneralSecurityException {
    decapsulate(
        HpkeUtil.AUTH_MODE,
        HpkeUtil.X25519_HKDF_SHA256_KEM_ID,
        HpkeUtil.HKDF_SHA256_KDF_ID,
        exportOnlyAeadId);
  }

  @Test
  public void decapsulate_failsWithInvalidMacAlgorithm() throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.BASE_MODE)).getTestSetup();
    byte[] validEncapsulatedKey = testSetup.encapsulatedKey;
    HpkeKemPrivateKey validRecipientPrivateKey =
        toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey);
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kem.decapsulate(validEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void authDecapsulate_failsWithInvalidMacAlgorithm() throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.AUTH_MODE)).getTestSetup();
    byte[] validEncapsulatedKey = testSetup.encapsulatedKey;
    byte[] senderPublicKey = testSetup.senderPublicKey;
    HpkeKemPrivateKey validRecipientPrivateKey =
        toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey);
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> kem.authDecapsulate(validEncapsulatedKey, validRecipientPrivateKey, senderPublicKey));
  }

  @Test
  public void decapsulate_failsWithInvalidEncapsulatedPublicKey() throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.BASE_MODE)).getTestSetup();
    byte[] invalidEncapsulatedKey =
        Arrays.copyOf(testSetup.encapsulatedKey, testSetup.encapsulatedKey.length + 2);
    HpkeKemPrivateKey validRecipientPrivateKey =
        toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey);
    assertThrows(
        InvalidKeyException.class,
        () -> kem.decapsulate(invalidEncapsulatedKey, validRecipientPrivateKey));
  }

  @Test
  public void authDecapsulate_failsWithInvalidEncapsulatedPublicKey()
      throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    HpkeTestSetup testSetup = testVectors.get(getDefaultTestId(HpkeUtil.AUTH_MODE)).getTestSetup();
    byte[] invalidEncapsulatedKey =
        Arrays.copyOf(testSetup.encapsulatedKey, testSetup.encapsulatedKey.length + 2);
    HpkeKemPrivateKey validRecipientPrivateKey =
        toHpkeKemPrivateKey(testSetup.recipientPrivateKey, testSetup.recipientPublicKey);
    byte[] senderPublicKey = testSetup.senderPublicKey;
    assertThrows(
        InvalidKeyException.class,
        () ->
            kem.authDecapsulate(invalidEncapsulatedKey, validRecipientPrivateKey, senderPublicKey));
  }

  @Test
  public void getKemId_succeeds() throws GeneralSecurityException {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf(MAC_ALGORITHM));
    expect.that(kem.getKemId()).isEqualTo(HpkeUtil.X25519_HKDF_SHA256_KEM_ID);
  }

  @Test
  public void getKemId_failsWithInvalidMacAlgorithm() {
    X25519HpkeKem kem = new X25519HpkeKem(new HkdfHpkeKdf("BadMac"));
    assertThrows(GeneralSecurityException.class, kem::getKemId);
  }
}
