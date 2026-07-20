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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingParameters.HashType;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

/** Test for {@code AesGcmHkdfStreamingAead}-implementation of {@code StreamingAead}-primitive. */
@RunWith(Theories.class)
public class AesGcmHkdfStreamingAeadTest {
  @Rule public TemporaryFolder tmpFolder = new TemporaryFolder();

  @DataPoints("vanillaImplementationTestVectors")
  public static AesGcmHkdfStreamingTestVector[] vanillaImplementationTestVectors;

  @DataPoints("randomAccessTestVectors")
  public static AesGcmHkdfStreamingTestVector[] randomAccessTestVectors;

  @DataPoints("singleBytesTestVectors")
  public static AesGcmHkdfStreamingTestVector[] singleBytesTestVectors;

  @DataPoints("skipWithStreamTestVectors")
  public static AesGcmHkdfStreamingTestVector[] skipWithStreamTestVectors;

  private static StreamingAead defaultAesHkdfStreamingInstance;

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   */
  @Theory
  public void testEncryptDecrypt(
      @FromDataPoints("vanillaImplementationTestVectors") AesGcmHkdfStreamingTestVector t)
      throws Exception {
    StreamingTestUtil.testEncryptDecrypt(
        t.ags, /* firstSegmentOffset= */ 0, t.plaintextSize, t.chunkSize);
  }

  /** Encrypt and then decrypt partially, and check that the result is the same. */
  @Theory
  public void testEncryptDecryptRandomAccess(
      @FromDataPoints("randomAccessTestVectors") AesGcmHkdfStreamingTestVector t) throws Exception {
    StreamingTestUtil.testEncryptDecryptRandomAccess(
        t.ags, /* firstSegmentOffset= */ 0, t.plaintextSize);
  }

  @Theory
  public void testEncryptSingleBytes(
      @FromDataPoints("singleBytesTestVectors") AesGcmHkdfStreamingTestVector t) throws Exception {
    StreamingTestUtil.testEncryptSingleBytes(t.ags, t.plaintextSize);
  }

  @Theory
  public void testSkipWithStream(
      @FromDataPoints("skipWithStreamTestVectors") AesGcmHkdfStreamingTestVector t)
      throws Exception {
    StreamingTestUtil.testSkipWithStream(
        t.ags, /* firstSegmentOffset= */ 0, t.plaintextSize, t.chunkSize);
  }

  /**
   * Encrypts and decrypts a with non-ASCII characters using CharsetEncoders and CharsetDecoders.
   */
  @Test
  public void testEncryptDecryptString() throws Exception {
    StreamingTestUtil.testEncryptDecryptString(defaultAesHkdfStreamingInstance);
  }

  /** Test encryption with a simulated ciphertext channel, which has only a limited capacity. */
  @Test
  public void testEncryptLimitedCiphertextChannel() throws Exception {
    // Test vector with a suitably large plaintext size.
    AesGcmHkdfStreamingTestVector t = singleBytesTestVectors[3];
    byte[] aad = Hex.decode("aabbccddeeff");
    byte[] plaintext = StreamingTestUtil.generatePlaintext(t.plaintextSize);
    ByteBuffer ciphertext =
        ByteBuffer.allocate(
            (int) ((AesGcmHkdfStreaming) t.ags).expectedCiphertextSize(t.plaintextSize));
    WritableByteChannel ctChannel = new SeekableByteBufferChannel(ciphertext, 100);
    WritableByteChannel encChannel = t.ags.newEncryptingChannel(ctChannel, aad);
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
    StreamingTestUtil.isValidCiphertext(t.ags, plaintext, aad, ciphertext.array());
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
    // Test vector with a short ikm.
    AesGcmHkdfStreamingTestVector t = vanillaImplementationTestVectors[0];
    StreamingTestUtil.testModifiedCiphertext(
        t.ags,
        ((AesGcmHkdfStreaming) t.ags).getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  @Test
  public void testModifiedCiphertextWithSeekableByteChannel() throws Exception {
    // Test vector with a short ikm.
    AesGcmHkdfStreamingTestVector t = vanillaImplementationTestVectors[0];
    StreamingTestUtil.testModifiedCiphertextWithSeekableByteChannel(
        t.ags,
        ((AesGcmHkdfStreaming) t.ags).getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /** Encrypt and decrypt a long ciphertext. */
  @Test
  public void testEncryptDecryptLong() throws Exception {
    if (TestUtil.isAndroid()) {
      System.out.println("testEncryptDecryptLong doesn't work on Android, skipping");
      return;
    }
    long plaintextSize = (1L << 32) + 1234567;
    StreamingTestUtil.testEncryptDecryptLong(defaultAesHkdfStreamingInstance, plaintextSize);
  }

  /** Encrypt some plaintext to a file, then decrypt from the file */
  @Test
  public void testFileEncryption() throws Exception {
    int plaintextSize = 1 << 20;
    StreamingTestUtil.testFileEncryption(
        defaultAesHkdfStreamingInstance, tmpFolder.newFile(), plaintextSize);
  }

  @BeforeClass
  public static void setUp() throws Exception {
    vanillaImplementationTestVectors =
        new AesGcmHkdfStreamingTestVector[] {
          // Ciphertext smaller than one segment.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA1,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 20,
              /* chunkSize= */ 64),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 400,
              /* chunkSize= */ 64),
          // Empty plaintext.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 0,
              /* chunkSize= */ 128),
          // Ciphertext contains more than one segment.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA1,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 1024,
              /* chunkSize= */ 128),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 3086,
              /* chunkSize= */ 128),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 32,
              /* ciphertextSegmentSize= */ 1024,
              HashType.SHA512,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 12345,
              /* chunkSize= */ 128),
          // During decryption large plaintext chunks are requested.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA1,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 1024,
              /* chunkSize= */ 4096),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 3086,
              /* chunkSize= */ 4096),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 32,
              /* ciphertextSegmentSize= */ 1024,
              HashType.SHA512,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 12345,
              /* chunkSize= */ 5000),
          // The ciphertext ends at a segment boundary.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA1,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 216,
              /* chunkSize= */ 64),
          // During decryption single bytes are requested.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 1024,
              /* chunkSize= */ 1),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA512,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 5086,
              /* chunkSize= */ 1)
        };
    // In the following test vectors the chunk sizes are zeroed since they are not needed for the
    // test.
    randomAccessTestVectors =
        new AesGcmHkdfStreamingTestVector[] {
          // The ciphertext is smaller than 1 segment.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 100,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 400,
              /* chunkSize= */ 0),
          // Empty plaintext.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 0,
              /* chunkSize= */ 0),
          // Ciphertext contains more than one segment.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 2048,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 4096,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 32,
              /* ciphertextSegmentSize= */ 1024,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 12345,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 4096,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 123456,
              /* chunkSize= */ 0),
          // The ciphertext ends at a segment boundary.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 216,
              /* chunkSize= */ 0),
        };
    singleBytesTestVectors =
        new AesGcmHkdfStreamingTestVector[] {
          // Encrypting with the stream writing single bytes. Chunk size isn't used for this test.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 1024,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 32,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 1024,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 12345,
              /* chunkSize= */ 0),
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 512,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 111111,
              /* chunkSize= */ 0),
        };
    skipWithStreamTestVectors =
        new AesGcmHkdfStreamingTestVector[] {
          // Smallest chunk size.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 4096,
              /* chunkSize= */ 1),
          // Chunk size < segmentSize.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA1,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 4096,
              /* chunkSize= */ 37),
          // Chunk size > segmentSize.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA512,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 4096,
              /* chunkSize= */ 384),
          // Chunk size > 3*segmentSize.
          new AesGcmHkdfStreamingTestVector(
              /* keySizeInBytes= */ 16,
              /* ciphertextSegmentSize= */ 256,
              HashType.SHA256,
              /* ikm= */ "000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff",
              /* plaintextSize= */ 4096,
              /* chunkSize= */ 800),
        };
    defaultAesHkdfStreamingInstance =
        AesGcmHkdfStreamingAead.create(
            AesGcmHkdfStreamingKey.create(
                AesGcmHkdfStreamingParameters.builder()
                    .setDerivedAesGcmKeySizeBytes(16)
                    .setKeySizeBytes(16)
                    .setCiphertextSegmentSizeBytes(4096)
                    .setHkdfHashType(HashType.SHA256)
                    .build(),
                SecretBytes.copyFrom(
                    Hex.decode("000102030405060708090a0b0c0d0e0f"),
                    InsecureSecretKeyAccess.get())));
  }

  private static final class AesGcmHkdfStreamingTestVector {
    final StreamingAead ags;
    final int plaintextSize;
    final int chunkSize;

    private AesGcmHkdfStreamingTestVector(
        int keySizeInBytes,
        int ciphertextSegmentSize,
        HashType hashType,
        String ikm,
        int plaintextSize,
        int chunkSize)
        throws GeneralSecurityException {
      AesGcmHkdfStreamingKey aesGcmHkdfStreamingKey =
          AesGcmHkdfStreamingKey.create(
              AesGcmHkdfStreamingParameters.builder()
                  .setDerivedAesGcmKeySizeBytes(keySizeInBytes)
                  .setKeySizeBytes(Hex.decode(ikm).length)
                  .setCiphertextSegmentSizeBytes(ciphertextSegmentSize)
                  .setHkdfHashType(hashType)
                  .build(),
              SecretBytes.copyFrom(Hex.decode(ikm), InsecureSecretKeyAccess.get()));
      this.ags = AesGcmHkdfStreamingAead.create(aesGcmHkdfStreamingKey);
      this.plaintextSize = plaintextSize;
      this.chunkSize = chunkSize;
    }
  }
}
