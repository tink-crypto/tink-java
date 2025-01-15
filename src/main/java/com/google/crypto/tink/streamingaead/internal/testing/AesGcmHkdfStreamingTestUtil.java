// Copyright 2025 Google LLC
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

package com.google.crypto.tink.streamingaead.internal.testing;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/** Test vectors for AesGcmHkdf StreamingAEAD. */
@AccessesPartialKey
public final class AesGcmHkdfStreamingTestUtil {
  /** From the cross language tests, test_manually_created_test_vector */
  private static StreamingAeadTestVector createTestVector0() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(16)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext =
        "This is a fairly long plaintext. It is of the exact length to create three output blocks. "
            .getBytes(UTF_8);
    byte[] headerLength = Hex.decode("18");
    byte[] salt = Hex.decode("93b3af5e14ab378d065addfc8484da64");
    byte[] noncePrefix = Hex.decode("2c0862877baea8");
    byte[] header = Bytes.concat(headerLength, salt, noncePrefix);

    byte[] c0 =
        Hex.decode(
            "db92d9c77406a406168478821c4298eab3e6d531277f4c1a051714faebcaefcbca7b7be05e9445ea");
    byte[] c1 =
        Hex.decode(
            "a0bb2904153398a25084dd80ae0edcd1c3079fcea2cd3770630ee36f7539207b8ec9d754956d486b71cdf989f0ed6fba6779b63558be0a66e668df14e1603cd2");
    byte[] c2 = Hex.decode("af8944844078345286d0b292e772e7190775c51a0f83e40c0b75821027e7e538e111");

    byte[] ciphertext = Bytes.concat(header, c0, c1, c2);
    byte[] aad = "aad".getBytes(UTF_8);
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // Empty plaintext, empty aad.
  private static StreamingAeadTestVector createTestVector1() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(16)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "18ec99b2c3884194023bd41bb9bff309205354c750fa0cb3c0d02609abf71f88eaeaa48d7deca27f");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // SHA256
  private static StreamingAeadTestVector createTestVector2() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(16)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "18be78bce0cab6fd38a9041eea8ab0ffc4cf17e3c00b661d3927f5f79069f41a210fedc40b25648c");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // SHA512
  private static StreamingAeadTestVector createTestVector3() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA512)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(16)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "18fec8139ccb406e0f140d7e2bcc41e1b899bc1b121574cc31d1c78ed2ca1cdf324665b8dce21095");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // 32 byte key
  private static StreamingAeadTestVector createTestVector4() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(16)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "180880e85a24207a7b72cefde26306ed09d7d76e58104b751d005a3ffd72dd6151f0d9c8ccf163f7");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // DerivedAesGcmKeySize = 32
  private static StreamingAeadTestVector createTestVector5() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(64)
            .setDerivedAesGcmKeySizeBytes(32)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // CiphertextSegmentSize = 128 (note: we can use the same ciphertext as for the above)
  private static StreamingAeadTestVector createTestVector6() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(128)
            .setDerivedAesGcmKeySizeBytes(32)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // CiphertextSegmentSize = 120, long plaintext (length 65).
  // Note: len(header) == 40, hence len(M0), first message block length, is 120 - 40 - 16 = 64
  // (see https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming)
  private static StreamingAeadTestVector createTestVector7() throws GeneralSecurityException {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA1)
            .setCiphertextSegmentSizeBytes(120)
            .setDerivedAesGcmKeySizeBytes(32)
            .build();
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext =
        "BLOCK 1.BLOCK 2.BLOCK 3.BLOCK 4.BLOCK 5.BLOCK 6.BLOCK 7.BLOCK 8.".getBytes(UTF_8);
    byte[] aad = new byte[] {0, 1, 2, 3};
    byte[] ciphertext =
        Hex.decode(
            "28782994617714a80fa085e15051a16854522330d6d0f26c049b2192f09cdd98b2eb90c753bfff277a29e54fa4afb15d648c28477eb07f012535c767f5fdce24ffffae318480c1d37357d6d3c511159318afa09ef38aa3f5456fd7817c5c02dd6e1a7fef174c8bd24e38b5982ac105497c0101ac5581fe5b");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  public static StreamingAeadTestVector[] createAesGcmHkdfTestVectors() {
    return exceptionIsBug(
        () ->
            new StreamingAeadTestVector[] {
              createTestVector0(),
              createTestVector1(),
              createTestVector2(),
              createTestVector3(),
              createTestVector4(),
              createTestVector5(),
              createTestVector6(),
              createTestVector7(),
            });
  }

  private AesGcmHkdfStreamingTestUtil() {}
}
