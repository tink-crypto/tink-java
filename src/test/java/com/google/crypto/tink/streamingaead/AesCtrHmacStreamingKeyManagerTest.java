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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.truth.Truth;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.streamingaead.internal.testing.AesCtrHmacStreamingTestUtil;
import com.google.crypto.tink.streamingaead.internal.testing.StreamingAeadTestVector;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.testing.StreamingTestUtil.ByteBufferChannel;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesCtrHmacStreamingKeyManager. */
@RunWith(Theories.class)
public class AesCtrHmacStreamingKeyManagerTest {
  @Before
  public void register() throws Exception {
    StreamingAeadConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
                    StreamingAead.class))
        .isNotNull();
  }

  @Test
  public void testSkip() throws Exception {
    Parameters parameters =
        AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2564KBTemplate().toParameters();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);

    int offset = 0;
    int plaintextSize = 1 << 16;
    // Runs the test with different sizes for the chunks to skip.
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
  }

  @Test
  public void createKey_multipleTimes_differentValues() throws Exception {
    Parameters parameters =
        AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2564KBTemplate().toParameters();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(parameters);
      com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey key =
          (com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getInitialKeyMaterial().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void getPrimitive_works() throws Exception {
    Parameters parameters =
        AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2564KBTemplate().toParameters();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    StreamingAead directAead =
        AesCtrHmacStreaming.create(
            (com.google.crypto.tink.streamingaead.AesCtrHmacStreamingKey) handle.getAt(0).getKey());

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        streamingAead, directAead, 0, 2049, 1000);
  }

  @Test
  public void testAes128CtrHmacSha2564KBTemplate() throws Exception {
    KeyTemplate template = AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2564KBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedKeySizeBytes(16)
                .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacTagSizeBytes(32)
                .setCiphertextSegmentSizeBytes(4 * 1024)
                .build());
  }

  @Test
  public void testAes128CtrHmacSha2561MBTemplate() throws Exception {
    KeyTemplate template = AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2561MBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedKeySizeBytes(16)
                .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacTagSizeBytes(32)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build());
  }

  @Test
  public void testAes256CtrHmacSha2564KBTemplate() throws Exception {
    KeyTemplate template = AesCtrHmacStreamingKeyManager.aes256CtrHmacSha2564KBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedKeySizeBytes(32)
                .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacTagSizeBytes(32)
                .setCiphertextSegmentSizeBytes(4 * 1024)
                .build());
  }

  @Test
  public void testAes256CtrHmacSha2561MBTemplate() throws Exception {
    KeyTemplate template = AesCtrHmacStreamingKeyManager.aes256CtrHmacSha2561MBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedKeySizeBytes(32)
                .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacTagSizeBytes(32)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .build());
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES128_CTR_HMAC_SHA256_4KB",
        "AES128_CTR_HMAC_SHA256_1MB",
        "AES256_CTR_HMAC_SHA256_4KB",
        "AES256_CTR_HMAC_SHA256_1MB"
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void serializeAndParse_works() throws Exception {
    Parameters parameters =
        AesCtrHmacStreamingKeyManager.aes128CtrHmacSha2561MBTemplate().toParameters();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    byte[] serializedHandle =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedHandle, InsecureSecretKeyAccess.get());
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }

  @DataPoints("testVectors")
  public static final StreamingAeadTestVector[] streamingTestVector =
      AesCtrHmacStreamingTestUtil.createAesCtrHmacTestVectors();

  @Theory
  public void decryptCiphertextInputStream_works(
      @FromDataPoints("testVectors") StreamingAeadTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
    @Nullable Integer id = v.getKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    InputStream plaintextStream =
        streamingAead.newDecryptingStream(
            new ByteArrayInputStream(v.getCiphertext()), v.getAssociatedData());
    byte[] decryption = new byte[v.getPlaintext().length];
    assertThat(plaintextStream.read(decryption)).isEqualTo(v.getPlaintext().length);
    assertThat(decryption).isEqualTo(v.getPlaintext());
    // There must be no more data available.
    assertThat(plaintextStream.read()).isEqualTo(-1);
  }

  // A test to create test vectors: If a test vector contains an empty ciphertext, this test will
  // fail with a possible ciphertext in the error message.
  @Theory
  public void encryptCiphertextInputStream_forCreation(
      @FromDataPoints("testVectors") StreamingAeadTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
    @Nullable Integer id = v.getKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
    OutputStream plaintextStream =
        streamingAead.newEncryptingStream(ciphertextStream, v.getAssociatedData());
    plaintextStream.write(v.getPlaintext());
    plaintextStream.close();

    Truth.assertWithMessage(
            "A possible ciphertext would be " + Hex.encode(ciphertextStream.toByteArray()))
        .that(v.getCiphertext())
        .isNotEmpty();
  }

  @Theory
  public void decryptCiphertextChannel_works(
      @FromDataPoints("testVectors") StreamingAeadTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
    @Nullable Integer id = v.getKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    ReadableByteChannel plaintextChannel =
        streamingAead.newDecryptingChannel(
            new ByteBufferChannel(v.getCiphertext()), v.getAssociatedData());
    ByteBuffer decryption = ByteBuffer.allocate(v.getPlaintext().length);
    assertThat(plaintextChannel.read(decryption)).isEqualTo(v.getPlaintext().length);
    assertThat(decryption.array()).isEqualTo(v.getPlaintext());
    // There must be no more data available.
    ByteBuffer endOfStreamChecker = ByteBuffer.allocate(1);
    assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(-1);
  }

  @Theory
  public void decryptSeekableByteChannel_works(
      @FromDataPoints("testVectors") StreamingAeadTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getKey()).makePrimary();
    @Nullable Integer id = v.getKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    StreamingAead streamingAead =
        handle.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    SeekableByteChannel plaintextChannel =
        streamingAead.newSeekableDecryptingChannel(
            new SeekableByteBufferChannel(v.getCiphertext()), v.getAssociatedData());
    // We move to some arbitrary place in the buffer and read the rest of the stream.
    int start = (v.getPlaintext().length + 1) / 2;
    int len = v.getPlaintext().length - start;
    plaintextChannel.position(start);
    ByteBuffer decryption = ByteBuffer.allocate(len);
    assertThat(plaintextChannel.read(decryption)).isEqualTo(len);
    assertThat(decryption.array())
        .isEqualTo(Arrays.copyOfRange(v.getPlaintext(), start, start + len));
    // There must be no more data available.
    ByteBuffer endOfStreamChecker = ByteBuffer.allocate(1);
    if (v.getPlaintext().length != 0) {
      assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(-1);
    } else {
      // TODO: b/390077226 - This should return -1.
      assertThat(plaintextChannel.read(endOfStreamChecker)).isEqualTo(0);
    }
  }
}
