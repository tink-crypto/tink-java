// Copyright 2026 Google LLC
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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link StreamingAeadConfig2026}. */
@RunWith(Theories.class)
public class StreamingAeadConfig2026Test {
  /**
   * A list of Keys which behave common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>create new keys with the same parameters
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   * </ul>
   */
  @DataPoints public static final Key[] keys = createKeys();

  private static Key[] createKeys() {
    try {
      return new Key[] {
        AesCtrHmacStreamingKey.create(
            AesCtrHmacStreamingParameters.builder()
                .setKeySizeBytes(48)
                .setDerivedKeySizeBytes(32)
                .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                .setHmacTagSizeBytes(16)
                .setCiphertextSegmentSizeBytes(60)
                .build(),
            SecretBytes.randomBytes(48)),
        AesGcmHkdfStreamingKey.create(
            AesGcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedAesGcmKeySizeBytes(32)
                .setCiphertextSegmentSizeBytes(100)
                .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                .build(),
            SecretBytes.randomBytes(32)),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Theory
  public void createKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle handle =
        KeysetHandle.generateNew(key.getParameters(), StreamingAeadConfig2026.get());

    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Theory
  public void serializeAndParseKey_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = StreamingAeadConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    Parameters parameters = key.getParameters();
    Configuration config = StreamingAeadConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_works(Key key) throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    StreamingAead streamingAead =
        keysetHandle.getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
    try (WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(Channels.newChannel(ciphertextStream), associatedData)) {
      ByteBuffer buffer = ByteBuffer.wrap(plaintext);
      while (buffer.hasRemaining()) {
        encryptingChannel.write(buffer);
      }
    }

    ByteArrayInputStream inputStream = new ByteArrayInputStream(ciphertextStream.toByteArray());
    ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(Channels.newChannel(inputStream), associatedData)) {
      ByteBuffer buffer = ByteBuffer.allocate(100);
      int read;
      while ((read = decryptingChannel.read(buffer)) != -1) {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        decryptedStream.write(bytes);
        buffer.clear();
      }
    }

    assertThat(decryptedStream.toByteArray()).isEqualTo(plaintext);
  }

  @Test
  public void createKey_withNonNullIdRequirement_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      return;
    }
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setCiphertextSegmentSizeBytes(100)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .build();
    Configuration config = StreamingAeadConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, 1234));
  }

  @Test
  public void get_throwsInFipsMode() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, StreamingAeadConfig2026::get);
    }
  }
}
