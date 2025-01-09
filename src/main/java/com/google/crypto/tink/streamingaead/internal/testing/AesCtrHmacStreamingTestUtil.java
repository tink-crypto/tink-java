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

package com.google.crypto.tink.streamingaead.internal.testing;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Test vectors for AesCtrHmac StreamingAEAD. */
@AccessesPartialKey
public final class AesCtrHmacStreamingTestUtil {
  private static byte[] xor(byte[] b1, byte[] b2) {
    assertThat(b1.length).isEqualTo(b2.length);
    byte[] result = new byte[b1.length];
    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) (b1[i] ^ b2[i]);
    }
    return result;
  }

  /**
   * A test vector which was created by hand for the cross language tests (see
   * aes_ctr_hmac_streaming_key_test there, and for more information about the magic values which
   * appear in this test.
   */
  private static StreamingAeadTestVector createTestVector0() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(32)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext =
        "This is a fairly long plaintext. However, it is not crazy long.".getBytes(UTF_8);
    byte[] headerLength = Hex.decode("18");
    byte[] salt = Hex.decode("93b3af5e14ab378d065addfc8484da64");
    byte[] noncePrefix = Hex.decode("2c0862877baea8");
    byte[] header = Bytes.concat(headerLength, salt, noncePrefix);

    byte[] msg0 = Arrays.copyOfRange(plaintext, 0, 8);
    byte[] msg1 = Arrays.copyOfRange(plaintext, 8, 40);
    byte[] msg2 = Arrays.copyOfRange(plaintext, 40, plaintext.length);

    byte[] c0 = xor(msg0, Hex.decode("ea8e18301bd57bfd"));
    byte[] c1 =
        xor(msg1, Hex.decode("2999c8ea5401704243c8cd77929fd52617fec5542a842446251bb2f3a81f6249"));
    byte[] c2 = xor(msg2, Hex.decode("70fe58e44835a6602952749e763637d9d973bca8358086"));
    byte[] tag0 = Hex.decode("8303ca71c04d8e06e1b01cff7c1178af47dac031517b1f6a2d9be84105677a68");
    byte[] tag1 = Hex.decode("834d890839f37f762caddc029cc673300ff107fd51f9a62058fcd00befc362e5");
    byte[] tag2 = Hex.decode("5fb0c893903271af38380c2f355cb85e5ec571648513123321bde0c6042f43c7");

    byte[] ciphertext = Bytes.concat(header, c0, tag0, c1, tag1, c2, tag2);
    byte[] aad = "aad".getBytes(UTF_8);
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  private static StreamingAeadTestVector createTestVector1() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacTagSizeBytes(32)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[] {};
    byte[] aad = new byte[0];
    byte[] ciphertext =
        Hex.decode(
            "1874eaeea1260b1cf44d00bfec6d7f58878ce2dd70d5844e2f4410a04703ec4c17ca8c8831be0f1711da64b5b893ca9f3ba643d6764fd787");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // Use SHA256/SHA512
  private static StreamingAeadTestVector createTestVector2() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(32)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[] {0, 1, 2, 3, 4, 5};
    byte[] ciphertext =
        Hex.decode(
            "18ae4fc7af4ed0433d33110793196ead8a77d2ae3f42db8425dc9e0789bdba7d5c23d61287fbe108224fbf11da38c8eaf5c9feab7deb9c62");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // Use SHA512/SHA1
  private static StreamingAeadTestVector createTestVector3() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA1)
            .setHmacTagSizeBytes(20)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("6eb56cdc726dfbe5d57f2fcdc6e9345b"), InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = new byte[] {0, 1, 2, 3, 4, 5};
    byte[] ciphertext =
        Hex.decode(
            "180d87a22c8979d8eb90163aa33aa09a02bab964d5bb2d7a035e62206d62807b3e9bb4984109ebeb3dfcbf43");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // Use KeySizeBytes=32
  private static StreamingAeadTestVector createTestVector4() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(16)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(20)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = Hex.decode("012345678901234567890123456789");
    byte[] ciphertext =
        Hex.decode(
            "18290c66c47a6095d947aa1671bd7b6d9c306e24d51d4b8a4f1b9db123a01226ebd2b6f7e05298a9f5908072");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  // Use DerivedKeySizeBytes=32
  private static StreamingAeadTestVector createTestVector5() throws GeneralSecurityException {
    AesCtrHmacStreamingParameters parameters =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedKeySizeBytes(32)
            .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA512)
            .setHmacTagSizeBytes(20)
            .setCiphertextSegmentSizeBytes(64)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            parameters,
            SecretBytes.copyFrom(
                Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"),
                InsecureSecretKeyAccess.get()));
    byte[] plaintext = new byte[0];
    byte[] aad = Hex.decode("012345678901234567890123456789");
    byte[] ciphertext =
        Hex.decode(
            "28f7bcc58e83e8e24bf833d8586c889ef465f52fdebcad6deb18be062c180e466de959eba1a884926692e496d85e1873a1bf9b46e56d76d83772bfc6");
    return new StreamingAeadTestVector(key, plaintext, aad, ciphertext);
  }

  public static StreamingAeadTestVector[] createAesCtrHmacTestVectors() {
    return exceptionIsBug(
        () ->
            new StreamingAeadTestVector[] {
              createTestVector0(),
              createTestVector1(),
              createTestVector2(),
              createTestVector3(),
              createTestVector4(),
              createTestVector5()
            });
  }

  private AesCtrHmacStreamingTestUtil() {}
}
