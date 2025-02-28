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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters.HashType;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for {@code AesCtrHmacStreaming}-implementation of {@code StreamingAead}-primitive.
 *
 * <p>TODO(b/66921440): adding more tests, including tests for other MAC and HKDF algos.
 */
@RunWith(JUnit4.class)
public class AesCtrHmacStreamingTest {
  @Rule public TemporaryFolder tmpFolder = new TemporaryFolder();

  private AesCtrHmacStreaming createAesCtrHmacStreaming() throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    String hkdfAlgo = "HmacSha256";
    int keySize = 16;
    String tagAlgo = "HmacSha256";
    int tagSize = 12;
    int segmentSize = 4096;
    int offset = 0;
    return new AesCtrHmacStreaming(ikm, hkdfAlgo, keySize, tagAlgo, tagSize, segmentSize, offset);
  }

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   *
   * @param keySizeInBytes the size of the AES key.
   * @param tagSizeInBytes the size of authentication tag.
   * @param segmentSize the size of the ciphertext segments.
   * @param firstSegmentOffset number of bytes prepended to the ciphertext stream.
   * @param plaintextSize the size of the plaintext
   * @param chunkSize decryption read chunks of this size.
   */
  public void testEncryptDecrypt(
      int keySizeInBytes,
      int tagSizeInBytes,
      int segmentSize,
      int firstSegmentOffset,
      int plaintextSize,
      int chunkSize)
      throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming ags =
        new AesCtrHmacStreaming(ikm, "HmacSha256", keySizeInBytes, "HmacSha256",
            tagSizeInBytes, segmentSize, firstSegmentOffset);
    StreamingTestUtil.testEncryptDecrypt(ags, firstSegmentOffset, plaintextSize, chunkSize);
  }

  /* The ciphertext is smaller than 1 segment */
  @Test
  public void testEncryptDecryptSmall() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 20, 64);
    testEncryptDecrypt(16, 12, 512, 0, 400, 64);
  }

  /* The ciphertext has a non-zero offset */
  @Test
  public void testEncryptDecryptSmallWithOffset() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 8, 20, 64);
    testEncryptDecrypt(16, 12, 512, 8, 400, 64);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptEmpty() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 0, 128);
    testEncryptDecrypt(16, 12, 256, 8, 0, 128);
  }

  /* The ciphertext contains more than 1 segment. */
  @Test
  public void testEncryptDecryptMedium() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 1024, 128);
    testEncryptDecrypt(16, 12, 512, 0, 3086, 128);
    testEncryptDecrypt(32, 12, 1024, 0, 12345, 128);
  }

  /* Test with different tag sizes */
  @Test
  public void testEncryptDecryptTagSize() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 512, 0, 5000, 128);
    testEncryptDecrypt(16, 16, 512, 0, 5000, 128);
    testEncryptDecrypt(16, 20, 512, 0, 5000, 128);
    testEncryptDecrypt(16, 32, 512, 0, 5000, 128);
  }

  /* During decryption large plaintext chunks are requested */
  @Test
  public void testEncryptDecryptLargeChunks() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 1024, 4096);
    testEncryptDecrypt(16, 12, 512, 0, 5086, 4096);
    testEncryptDecrypt(32, 16, 1024, 0, 12345, 5000);
  }

  @Test
  public void testEncryptDecryptMediumWithOffset() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 8, 1024, 64);
    testEncryptDecrypt(16, 12, 512, 20, 3086, 256);
    testEncryptDecrypt(32, 16, 1024, 10, 12345, 5000);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptLastSegmentFull() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 216, 64);
    testEncryptDecrypt(16, 12, 256, 16, 200, 256);
    testEncryptDecrypt(16, 12, 256, 16, 440, 1024);
  }

  /* During decryption single bytes are requested */
  @Test
  public void testEncryptDecryptSingleBytes() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 1024, 1);
    testEncryptDecrypt(32, 12, 512, 0, 5086, 1);
  }

  /** Encrypt and then decrypt partially, and check that the result is the same. */
  public void testEncryptDecryptRandomAccess(
      int keySizeInBytes,
      int tagSizeInBytes,
      int segmentSize,
      int firstSegmentOffset,
      int plaintextSize)
      throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming ags =
        new AesCtrHmacStreaming(ikm, "HmacSha256", keySizeInBytes, "HmacSha256",
            tagSizeInBytes, segmentSize, firstSegmentOffset);
    StreamingTestUtil.testEncryptDecryptRandomAccess(ags, firstSegmentOffset, plaintextSize);
  }

  /* The ciphertext is smaller than 1 segment. */
  @Test
  public void testEncryptDecryptRandomAccessSmall() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 0, 100);
    testEncryptDecryptRandomAccess(16, 12, 512, 0, 400);
  }

  @Test
  public void testEncryptDecryptRandomAccessSmallWithOffset() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 8, 20);
    testEncryptDecryptRandomAccess(16, 12, 256, 8, 100);
    testEncryptDecryptRandomAccess(16, 12, 512, 8, 400);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptRandomAccessEmpty() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 0, 0);
    testEncryptDecryptRandomAccess(16, 12, 256, 8, 0);
  }

  @Test
  public void testEncryptDecryptRandomAccessMedium() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 0, 2048);
    testEncryptDecryptRandomAccess(16, 12, 256, 0, 4096);
    testEncryptDecryptRandomAccess(32, 16, 1024, 0, 12345);
  }

  @Test
  public void testEncryptDecryptRandomAccessMediumWithOffset() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 8, 2048);
    testEncryptDecryptRandomAccess(16, 12, 256, 10, 4096);
    testEncryptDecryptRandomAccess(32, 16, 1024, 20, 12345);
    testEncryptDecryptRandomAccess(16, 12, 4096, 0, 123456);
  }

  /* Test with different tag sizes */
  @Test
  public void testEncryptDecryptRandomAccessTagSize() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 512, 0, 12345);
    testEncryptDecryptRandomAccess(16, 16, 512, 0, 5000);
    testEncryptDecryptRandomAccess(16, 20, 512, 0, 4096);
    testEncryptDecryptRandomAccess(16, 32, 512, 0, 4096);
    testEncryptDecryptRandomAccess(16, 16, 256, 16, 440);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptRandomAccessLastSegmentFull() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 0, 216);
    testEncryptDecryptRandomAccess(16, 12, 256, 16, 200);
    testEncryptDecryptRandomAccess(16, 12, 256, 16, 440);
  }

  @Test
  public void testNegativeFirstSegmentOffset_throws() throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesCtrHmacStreaming(
                ikm,
                "HmacSha256",
                /* keySizeInBytes= */ 16,
                "HmacSha256",
                /* tagSizeInBytes= */ 12,
                /* ciphertextSegmentSize= */ 4096,
                /* firstSegmentOffset= */ -1));
  }

  /**
   * One case that is sometimes problematic is writing single bytes to a stream. This test
   * constructs an OutputStream from a WritableByteChannel and tests whether encryption works on
   * this stream.
   */
  public void testEncryptSingleBytes(int keySizeInBytes, int plaintextSize) throws Exception {
    int firstSegmentOffset = 0;
    int segmentSize = 512;
    int tagSizeInBytes = 12;
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming ags = new AesCtrHmacStreaming(ikm, "HmacSha256", keySizeInBytes,
        "HmacSha256", tagSizeInBytes, segmentSize, firstSegmentOffset);
    StreamingTestUtil.testEncryptSingleBytes(ags, plaintextSize);
  }

  /* Encryption is done byte by byte. */
  @Test
  public void testEncryptWithStream() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptSingleBytes(16, 1024);
    testEncryptSingleBytes(16, 12345);
    testEncryptSingleBytes(16, 111111);
  }

  /**
   * Encrypts and decrypts a with non-ASCII characters using CharsetEncoders and CharsetDecoders.
   */
  @Test
  public void testEncryptDecryptString() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    StreamingTestUtil.testEncryptDecryptString(createAesCtrHmacStreaming());
  }

  /** Test encryption with a simulated ciphertext channel, which has only a limited capacity. */
  @Test
  public void testEncryptLimitedCiphertextChannel() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    int segmentSize = 512;
    int firstSegmentOffset = 0;
    int keySizeInBytes = 16;
    int tagSizeInBytes = 12;
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming ags = new AesCtrHmacStreaming(ikm, "HmacSha256", keySizeInBytes,
        "HmacSha256", tagSizeInBytes, segmentSize, firstSegmentOffset);

    int plaintextSize = 1 << 15;
    int maxChunkSize = 100;
    byte[] aad = Hex.decode("aabbccddeeff");
    byte[] plaintext = StreamingTestUtil.generatePlaintext(plaintextSize);
    int ciphertextLength = (int) ags.expectedCiphertextSize(plaintextSize);
    ByteBuffer ciphertext = ByteBuffer.allocate(ciphertextLength);
    WritableByteChannel ctChannel = new SeekableByteBufferChannel(ciphertext, maxChunkSize);
    WritableByteChannel encChannel = ((StreamingAead) ags).newEncryptingChannel(ctChannel, aad);
    ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);
    int loops = 0;
    while (plaintextBuffer.remaining() > 0) {
      encChannel.write(plaintextBuffer);
      loops += 1;
      if (loops > 100000) {
        fail("Too many loops");
      }
    }
    encChannel.close();
    assertFalse(encChannel.isOpen());
    StreamingTestUtil.isValidCiphertext(ags, plaintext, aad, ciphertext.array());
  }

  // Modifies the ciphertext. Checks that decryption either results in correct plaintext
  // or an exception.
  // The following modifications are tested:
  // (1) truncate ciphertext
  // (2) append stuff
  // (3) flip bits
  // (4) remove segments
  // (5) duplicate segments
  // (6) modify aad
  @Test
  public void testModifiedCiphertext() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    int offset = 8;
    AesCtrHmacStreaming ags = new AesCtrHmacStreaming(ikm, "HmacSha256", keySize,
        "HmacSha256", tagSize, segmentSize, offset);
    StreamingTestUtil.testModifiedCiphertext(ags, segmentSize, offset);
  }

  @Test
  public void testSkipWithStream() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    int offset = 8;
    int plaintextSize = 1 << 16;
    AesCtrHmacStreaming ags =
        new AesCtrHmacStreaming(
            ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize, offset);
    // Smallest possible chunk size
    StreamingTestUtil.testSkipWithStream(ags, offset, plaintextSize, 1);
    // Chunk size < segmentSize
    StreamingTestUtil.testSkipWithStream(ags, offset, plaintextSize, 37);
    // Chunk size > segmentSize
    StreamingTestUtil.testSkipWithStream(ags, offset, plaintextSize, 384);
    // Chunk size > 3*segmentSize
    StreamingTestUtil.testSkipWithStream(ags, offset, plaintextSize, 800);
  }

  @Test
  public void testModifiedCiphertextWithSeekableByteChannel() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    int offset = 8;
    AesCtrHmacStreaming ags = new AesCtrHmacStreaming(ikm, "HmacSha256", keySize,
        "HmacSha256", tagSize, segmentSize, offset);
    StreamingTestUtil.testModifiedCiphertextWithSeekableByteChannel(ags, segmentSize, offset);
  }

  @Test
  /*
   * Encrypts a plaintext consisting of 0's and checks that the ciphertext has no repeating blocks.
   * This is a simple test to catch basic errors that violate semantic security. The probability of
   * false positives is smaller than 2^{-100}.
   */
  public void testKeyStream() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    HashSet<String> ciphertextBlocks = new HashSet<String>();
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    byte[] aad = Hex.decode("aabbccddeeff");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    int offset = 0;
    int plaintextSize = 2000;
    int samples = 8;
    int blocksize = 16;
    AesCtrHmacStreaming ags = new AesCtrHmacStreaming(
        ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize, offset);
    byte[] plaintext = new byte[plaintextSize];
    for (int sample = 0; sample < samples; sample++) {
      byte[] ciphertext =
          StreamingTestUtil.encryptWithChannel(ags, plaintext, aad, ags.getFirstSegmentOffset());
      for (int pos = ags.getHeaderLength(); pos + blocksize <= ciphertext.length; pos++) {
        String block = Hex.encode(Arrays.copyOfRange(ciphertext, pos, pos + blocksize));
        if (!ciphertextBlocks.add(block)) {
          fail("Ciphertext contains a repeating block " + block + " at position " + pos);
        }
      }
    }
  }

  /** Encrypt and decrypt a long ciphertext. */
  @Test
  public void testEncryptDecryptLong() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    long plaintextSize = (1L << 26) + 1234567;
    StreamingTestUtil.testEncryptDecryptLong(createAesCtrHmacStreaming(), plaintextSize);
  }

  /** Encrypt some plaintext to a file, then decrypt from the file */
  @Test
  public void testFileEncryption() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    int plaintextSize = 1 << 20;
    StreamingTestUtil.testFileEncryption(
        createAesCtrHmacStreaming(), tmpFolder.newFile(), plaintextSize);
  }

  @Test
  public void testFailIfFipsModeUsed() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    assertThrows(GeneralSecurityException.class, () -> testEncryptDecrypt(16, 12, 256, 0, 20, 64));
  }

  @Test
  public void testCompareConstructorToCreate_basic_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 16,
            "HmacSha256",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_differentKeySize_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 16,
            "HmacSha256",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_differentDerivedKeySize_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 32,
            "HmacSha256",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(32)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_differentTagSize_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 16,
            "HmacSha256",
            /* tagSizeInBytes= */ 17,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(17)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_differentSegmentSize_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 16,
            "HmacSha256",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 128,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(128)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_varyHkdfType_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha1",
            /* keySizeInBytes= */ 16,
            "HmacSha256",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA1)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA256)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_varyHmacType_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha256",
            /* keySizeInBytes= */ 16,
            "HmacSha512",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA256)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA512)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testCompareConstructorToCreate_varyHkdfAndHmacType_works() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreaming constructorAead =
        new AesCtrHmacStreaming(
            ikm,
            "HmacSha512",
            /* keySizeInBytes= */ 16,
            "HmacSha1",
            /* tagSizeInBytes= */ 12,
            /* ciphertextSegmentSize= */ 256,
            /* firstSegmentOffset= */ 0);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA512)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA1)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead createMethodAead = AesCtrHmacStreaming.create(key);

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        constructorAead, createMethodAead, 0, 2049, 1000);
  }

  @Test
  public void testB289805133() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    // The initial key material is irrelevant (but needs to be of the correct size)
    byte[] ikm =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff"
                + "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(HashType.SHA512)
            .setDerivedKeySizeBytes(16)
            .setHmacHashType(HashType.SHA1)
            .setHmacTagSizeBytes(12)
            .setCiphertextSegmentSizeBytes(256)
            .build();
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
    StreamingAead streamingAead = AesCtrHmacStreaming.create(key);
    // The associated data is irrelevant.
    byte[] associatedData = Random.randBytes(15);
    // Somewhat long plaintext -- the exact value is irrelevant.
    byte[] plaintext = Random.randBytes(1100);
    // Get ciphertext
    byte[] ciphertext;
    {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try (OutputStream encChannel = streamingAead.newEncryptingStream(bos, associatedData)) {
        encChannel.write(plaintext);
      }
      ciphertext = bos.toByteArray();
    }
    StreamingTestUtil.SeekableByteBufferChannel ctChannel =
        new StreamingTestUtil.SeekableByteBufferChannel(ciphertext);
    SeekableByteChannel ptChannel =
        streamingAead.newSeekableDecryptingChannel(ctChannel, associatedData);

    // First make a read which reads to the end.
    ByteBuffer decrypted = ByteBuffer.allocate(100);
    ptChannel.position(1000);
    assertThat(ptChannel.read(decrypted)).isEqualTo(100);

    // Now allocate an empty buffer and try to read from within the stream.
    ByteBuffer empty = ByteBuffer.allocate(0);
    ptChannel.position(500);
    assertThat(ptChannel.read(empty)).isEqualTo(0);
  }
}
