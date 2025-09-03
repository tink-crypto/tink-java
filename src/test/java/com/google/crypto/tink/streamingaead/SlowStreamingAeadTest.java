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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the StreamingAead where the channel only reads/writes a small number of bytes. */
@RunWith(Theories.class)
public final class SlowStreamingAeadTest {

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
  }

  /**
   * A {@link WritableByteChannel} that writes at most 2 bytes at a time.
   *
   * <p>If the input is non-empty, it writes at least one byte.
   */
  private static final class SlowWritableByteChannel implements WritableByteChannel {
    private final WritableByteChannel channel;

    SlowWritableByteChannel(WritableByteChannel channel) {
      this.channel = channel;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
      if (src.remaining() <= 2) {
        return channel.write(src);
      }
      byte[] bytes = new byte[2];
      src.get(bytes);
      return channel.write(ByteBuffer.wrap(bytes));
    }

    @Override
    public boolean isOpen() {
      return channel.isOpen();
    }

    @Override
    public void close() throws IOException {
      channel.close();
    }
  }

  /**
   * A {@link ReadableByteChannel} that reads at most 2 bytes at a time.
   *
   * <p>Note that reads toggle between non-empty and empty reads.
   */
  private static final class SlowReadableByteChannel implements ReadableByteChannel {
    private final ReadableByteChannel channel;

    SlowReadableByteChannel(ReadableByteChannel channel) {
      this.channel = channel;
    }

    boolean nextReadNothing = true;

    @Override
    public int read(ByteBuffer dst) throws IOException {
      if (nextReadNothing) {
        nextReadNothing = false;
        return 0;
      }
      nextReadNothing = true;

      if (dst.remaining() <= 2) {
        return channel.read(dst);
      }
      ByteBuffer buffer = ByteBuffer.allocate(2);
      int bytesRead = channel.read(buffer);
      buffer.flip();
      dst.put(buffer);
      return bytesRead;
    }

    @Override
    public boolean isOpen() {
      return channel.isOpen();
    }

    @Override
    public void close() throws IOException {
      channel.close();
    }
  }

  @DataPoints("templates")
  public static final String[] templates =
      new String[] {
        "AES128_GCM_HKDF_4KB",
        "AES128_CTR_HMAC_SHA256_4KB",
      };

  @Theory
  public void encryptDecrypt_withSlowChannels_works(
      @FromDataPoints("templates") String templateName) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    StreamingAead streamingAead =
        handle.getPrimitive(StreamingAeadConfigurationV1.get(), StreamingAead.class);

    byte[] plaintext = new byte[42 * 1024];
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);

    // Encrypt with a slow writable channel.
    ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
    WritableByteChannel slowWritableByteChannel =
        new SlowWritableByteChannel(Channels.newChannel(ciphertextOutputStream));
    try (WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(slowWritableByteChannel, associatedData)) {
      while (plaintextBuffer.remaining() > 0) {
        encryptingChannel.write(plaintextBuffer);
      }
    }

    byte[] ciphertext = ciphertextOutputStream.toByteArray();

    // Decrypt with a slow readable channel.
    ReadableByteChannel ciphertextSource =
        new SlowReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(ciphertext)));
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(ciphertextSource, associatedData)) {
      int bytesToRead = plaintext.length;
      ByteBuffer decrypted = ByteBuffer.allocate(bytesToRead);

      int bytesRead = 0;
      while (bytesRead < bytesToRead) {
        int n = decryptingChannel.read(decrypted);
        if (n == -1) {
          throw new IOException(
              "Unexpected end of stream, bytesRead: "
                  + bytesRead
                  + ", bytesToRead: "
                  + bytesToRead);
        }
        bytesRead += n;
      }
      assertThat(decrypted.array()).isEqualTo(plaintext);
    }
  }

  // A small test that shows that SlowWritableByteChannel correctly implements WritableByteChannel.
  @Test
  public void slowWritableByteChannel_works() throws Exception {
    byte[] input = "some input".getBytes(UTF_8);
    ByteBuffer plaintextBuffer = ByteBuffer.wrap(input);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    WritableByteChannel slowWritableByteChannel =
        new SlowWritableByteChannel(Channels.newChannel(outputStream));
    while (plaintextBuffer.remaining() > 0) {
      slowWritableByteChannel.write(plaintextBuffer);
    }
    assertThat(outputStream.toByteArray()).isEqualTo(input);
  }

  // A small test that shows that SlowReadableByteChannel correctly implements ReadableByteChannel.
  @Test
  public void slowReadableByteChannel_works() throws Exception {
    byte[] input = "some input".getBytes(UTF_8);

    ReadableByteChannel source =
        new SlowReadableByteChannel(Channels.newChannel(new ByteArrayInputStream(input)));

    ByteBuffer output = ByteBuffer.allocate(input.length);

    int bytesRead = 0;
    while (bytesRead < input.length) {
      int n = source.read(output);
      if (n == -1) {
        throw new IOException("Unexpected end of stream");
      }
      bytesRead += n;
    }
    assertThat(output.array()).isEqualTo(input);
  }
}
