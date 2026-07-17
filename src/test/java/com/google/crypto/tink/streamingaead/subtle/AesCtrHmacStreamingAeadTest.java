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

package com.google.crypto.tink.streamingaead.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters;
import com.google.crypto.tink.streamingaead.AesCtrHmacStreamingParameters.HashType;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.crypto.tink.testing.TestUtil;
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

/** Unit tests for {@link AesCtrHmacStreamingAead}. */
@RunWith(JUnit4.class)
@LowLevelCryptoCaller
public class AesCtrHmacStreamingAeadTest {
  @Rule public TemporaryFolder tmpFolder = new TemporaryFolder();

  private static AesCtrHmacStreamingKey createKey(
      byte[] ikm, String hkdfAlgo, int derivedKeySize, String tagAlgo, int tagSize, int segmentSize)
      throws Exception {
    HashType hkdfHash = getHashType(hkdfAlgo);
    HashType hmacHash = getHashType(tagAlgo);
    AesCtrHmacStreamingParameters params =
        AesCtrHmacStreamingParameters.builder()
            .setKeySizeBytes(ikm.length)
            .setHkdfHashType(hkdfHash)
            .setDerivedKeySizeBytes(derivedKeySize)
            .setHmacHashType(hmacHash)
            .setHmacTagSizeBytes(tagSize)
            .setCiphertextSegmentSizeBytes(segmentSize)
            .build();
    return AesCtrHmacStreamingKey.create(
        params, SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()));
  }

  private static HashType getHashType(String algo) throws GeneralSecurityException {
    switch (algo) {
      case "HmacSha1":
        return HashType.SHA1;
      case "HmacSha256":
        return HashType.SHA256;
      case "HmacSha512":
        return HashType.SHA512;
      default:
        throw new GeneralSecurityException("Unknown hash type: " + algo);
    }
  }

  private StreamingAead createAesCtrHmacStreaming() throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    AesCtrHmacStreamingKey key =
        createKey(
            ikm,
            "HmacSha256",
            /* derivedKeySize= */ 16,
            "HmacSha256",
            /* tagSize= */ 12,
            /* segmentSize= */ 4096);
    return AesCtrHmacStreamingAead.create(key);
  }

  @Test
  public void create_nullKey_throws() throws Exception {
    assertThrows(NullPointerException.class, () -> AesCtrHmacStreamingAead.create(null));
  }

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   *
   * @param keySizeInBytes the size of the AES key.
   * @param tagSizeInBytes the size of authentication tag.
   * @param segmentSize the size of the ciphertext segments.
   * @param plaintextSize the size of the plaintext
   * @param chunkSize decryption read chunks of this size.
   */
  public void testEncryptDecrypt(
      int keySizeInBytes, int tagSizeInBytes, int segmentSize, int plaintextSize, int chunkSize)
      throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySizeInBytes, "HmacSha256", tagSizeInBytes, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    StreamingTestUtil.testEncryptDecrypt(
        ags, /* firstSegmentOffset= */ 0, plaintextSize, chunkSize);
  }

  /* The ciphertext is smaller than 1 segment */
  @Test
  public void testEncryptDecryptSmall() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 20, 64);
    testEncryptDecrypt(16, 12, 512, 400, 64);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptEmpty() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 0, 128);
  }

  /* The ciphertext contains more than 1 segment. */
  @Test
  public void testEncryptDecryptMedium() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 1024, 128);
    testEncryptDecrypt(16, 12, 512, 3086, 128);
    testEncryptDecrypt(32, 12, 1024, 12345, 128);
  }

  /* Test with different tag sizes */
  @Test
  public void testEncryptDecryptTagSize() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 512, 5000, 128);
    testEncryptDecrypt(16, 16, 512, 5000, 128);
    testEncryptDecrypt(16, 20, 512, 5000, 128);
    testEncryptDecrypt(16, 32, 512, 5000, 128);
  }

  /* During decryption large plaintext chunks are requested */
  @Test
  public void testEncryptDecryptLargeChunks() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 1024, 4096);
    testEncryptDecrypt(16, 12, 512, 5086, 4096);
    testEncryptDecrypt(32, 16, 1024, 12345, 5000);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptLastSegmentFull() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 216, 64);
  }

  /* During decryption single bytes are requested */
  @Test
  public void testEncryptDecryptSingleBytes() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecrypt(16, 12, 256, 1024, 1);
    testEncryptDecrypt(32, 12, 512, 5086, 1);
  }

  /** Encrypt and then decrypt partially, and check that the result is the same. */
  public void testEncryptDecryptRandomAccess(
      int keySizeInBytes, int tagSizeInBytes, int segmentSize, int plaintextSize) throws Exception {
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySizeInBytes, "HmacSha256", tagSizeInBytes, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    StreamingTestUtil.testEncryptDecryptRandomAccess(
        ags, /* firstSegmentOffset= */ 0, plaintextSize);
  }

  /* The ciphertext is smaller than 1 segment. */
  @Test
  public void testEncryptDecryptRandomAccessSmall() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 100);
    testEncryptDecryptRandomAccess(16, 12, 512, 400);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptRandomAccessEmpty() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 0);
  }

  @Test
  public void testEncryptDecryptRandomAccessMedium() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 2048);
    testEncryptDecryptRandomAccess(16, 12, 256, 4096);
    testEncryptDecryptRandomAccess(32, 16, 1024, 12345);
  }

  /* Test with different tag sizes */
  @Test
  public void testEncryptDecryptRandomAccessTagSize() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 512, 12345);
    testEncryptDecryptRandomAccess(16, 16, 512, 5000);
    testEncryptDecryptRandomAccess(16, 20, 512, 4096);
    testEncryptDecryptRandomAccess(16, 32, 512, 4096);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptRandomAccessLastSegmentFull() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testEncryptDecryptRandomAccess(16, 12, 256, 216);
  }

  /**
   * One case that is sometimes problematic is writing single bytes to a stream. This test
   * constructs an OutputStream from a WritableByteChannel and tests whether encryption works on
   * this stream.
   */
  public void testEncryptSingleBytes(int keySizeInBytes, int plaintextSize) throws Exception {
    int segmentSize = 512;
    int tagSizeInBytes = 12;
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySizeInBytes, "HmacSha256", tagSizeInBytes, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
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
    int keySizeInBytes = 16;
    int tagSizeInBytes = 12;
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff");
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySizeInBytes, "HmacSha256", tagSizeInBytes, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);

    int plaintextSize = 1 << 15;
    int maxChunkSize = 100;
    byte[] aad = Hex.decode("aabbccddeeff");
    byte[] plaintext = StreamingTestUtil.generatePlaintext(plaintextSize);
    int ciphertextLength = (int) ((AesCtrHmacStreaming) ags).expectedCiphertextSize(plaintextSize);
    ByteBuffer ciphertext = ByteBuffer.allocate(ciphertextLength);
    WritableByteChannel ctChannel = new SeekableByteBufferChannel(ciphertext, maxChunkSize);
    WritableByteChannel encChannel = ags.newEncryptingChannel(ctChannel, aad);
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
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    StreamingTestUtil.testModifiedCiphertext(ags, segmentSize, /* firstSegmentOffset= */ 0);
  }

  @Test
  public void testSkipWithStream() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    int plaintextSize = 1 << 16;
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    // Smallest possible chunk size
    StreamingTestUtil.testSkipWithStream(ags, /* firstSegmentOffset= */ 0, plaintextSize, 1);
    // Chunk size < segmentSize
    StreamingTestUtil.testSkipWithStream(ags, /* firstSegmentOffset= */ 0, plaintextSize, 37);
    // Chunk size > segmentSize
    StreamingTestUtil.testSkipWithStream(ags, /* firstSegmentOffset= */ 0, plaintextSize, 384);
    // Chunk size > 3*segmentSize
    StreamingTestUtil.testSkipWithStream(ags, /* firstSegmentOffset= */ 0, plaintextSize, 800);
  }

  @Test
  public void testModifiedCiphertextWithSeekableByteChannel() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    Assume.assumeFalse(TestUtil.isTsan());
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 256;
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    StreamingTestUtil.testModifiedCiphertextWithSeekableByteChannel(
        ags, segmentSize, /* firstSegmentOffset= */ 0);
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
    int plaintextSize = 2000;
    int samples = 8;
    int blocksize = 16;
    AesCtrHmacStreamingKey key =
        createKey(ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize);
    StreamingAead ags = AesCtrHmacStreamingAead.create(key);
    byte[] plaintext = new byte[plaintextSize];
    for (int sample = 0; sample < samples; sample++) {
      byte[] ciphertext =
          StreamingTestUtil.encryptWithChannel(ags, plaintext, aad, /* firstSegmentOffset= */ 0);
      for (int pos = ((AesCtrHmacStreaming) ags).getHeaderLength();
          pos + blocksize <= ciphertext.length;
          pos++) {
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
    Assume.assumeFalse(TestUtil.isTsan());

    long plaintextSize = (1L << 26) + 1234567;
    StreamingTestUtil.testEncryptDecryptLong(createAesCtrHmacStreaming(), plaintextSize);
  }

  /** Encrypt some plaintext to a file, then decrypt from the file */
  @Test
  public void testFileEncryption() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    Assume.assumeFalse(TestUtil.isTsan());

    int plaintextSize = 1 << 20;
    StreamingTestUtil.testFileEncryption(
        createAesCtrHmacStreaming(), tmpFolder.newFile(), plaintextSize);
  }

  @Test
  public void testFailIfFipsModeUsed() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    assertThrows(GeneralSecurityException.class, () -> testEncryptDecrypt(16, 12, 256, 20, 64));
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
    StreamingAead streamingAead = AesCtrHmacStreamingAead.create(key);
    // The associated data is irrelevant.
    byte[] associatedData = com.google.crypto.tink.subtle.Random.randBytes(15);
    // Somewhat long plaintext -- the exact value is irrelevant.
    byte[] plaintext = com.google.crypto.tink.subtle.Random.randBytes(1100);
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
