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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.streamingaead.subtle.AesCtrHmacStreamingAead;
import com.google.crypto.tink.streamingaead.subtle.AesGcmHkdfStreamingAead;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for StreamingAead which run under FIPS mode.
 *
 * <p>We test this by tagging the test with "fips" which runs it under two build configurations:
 *
 * <ul>
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=False}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 * </ul>
 */
@RunWith(JUnit4.class)
public final class FipsTest {

  private static AesCtrHmacStreamingParameters createAesCtrHmacParameters()
      throws GeneralSecurityException {
    return AesCtrHmacStreamingParameters.builder()
        .setKeySizeBytes(32)
        .setDerivedKeySizeBytes(16)
        .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
        .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
        .setHmacTagSizeBytes(12)
        .setCiphertextSegmentSizeBytes(256)
        .build();
  }

  private static AesGcmHkdfStreamingParameters createAesGcmHkdfParameters()
      throws GeneralSecurityException {
    return AesGcmHkdfStreamingParameters.builder()
        .setKeySizeBytes(32)
        .setDerivedAesGcmKeySizeBytes(16)
        .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
        .setCiphertextSegmentSizeBytes(256)
        .build();
  }

  @Test
  public void streamingAeadConfig2026() throws Exception {
    assertThat(StreamingAeadConfig2026.get()).isNotNull();

    AesCtrHmacStreamingParameters ctrHmacParams = createAesCtrHmacParameters();
    AesGcmHkdfStreamingParameters gcmHkdfParams = createAesGcmHkdfParameters();
    KeysetHandle ctrHmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesCtrHmacStreamingKey.create(
                            ctrHmacParams,
                            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get())))
                    .withRandomId()
                    .makePrimary())
            .build();
    KeysetHandle gcmHkdfHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesGcmHkdfStreamingKey.create(
                            gcmHkdfParams,
                            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get())))
                    .withRandomId()
                    .makePrimary())
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ctrHmacParams, StreamingAeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(gcmHkdfParams, StreamingAeadConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> ctrHmacHandle.getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> gcmHkdfHandle.getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class));
    } else {
      assertThat(KeysetHandle.generateNew(ctrHmacParams, StreamingAeadConfig2026.get()))
          .isNotNull();
      assertThat(KeysetHandle.generateNew(gcmHkdfParams, StreamingAeadConfig2026.get()))
          .isNotNull();
      assertThat(ctrHmacHandle.getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class))
          .isNotNull();
      assertThat(gcmHkdfHandle.getPrimitive(StreamingAeadConfig2026.get(), StreamingAead.class))
          .isNotNull();
    }
  }

  @Test
  public void aesCtrHmacStreamingConstructor() throws Exception {
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () ->
              new AesCtrHmacStreaming(
                  new byte[32],
                  "HmacSha256",
                  /* keySizeInBytes= */ 16,
                  "HmacSha256",
                  /* tagSizeInBytes= */ 12,
                  /* ciphertextSegmentSize= */ 256,
                  /* firstSegmentOffset= */ 0));
    } else {
      assertThat(
              new AesCtrHmacStreaming(
                  new byte[32],
                  "HmacSha256",
                  /* keySizeInBytes= */ 16,
                  "HmacSha256",
                  /* tagSizeInBytes= */ 12,
                  /* ciphertextSegmentSize= */ 256,
                  /* firstSegmentOffset= */ 0))
          .isNotNull();
    }
  }

  @Test
  public void aesGcmHkdfStreamingConstructor() throws Exception {
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          IllegalStateException.class,
          () ->
              new AesGcmHkdfStreaming(
                  new byte[32],
                  "HmacSha256",
                  /* keySizeInBytes= */ 16,
                  /* ciphertextSegmentSize= */ 256,
                  /* firstSegmentOffset= */ 0));
    } else {
      assertThat(
              new AesGcmHkdfStreaming(
                  new byte[32],
                  "HmacSha256",
                  /* keySizeInBytes= */ 16,
                  /* ciphertextSegmentSize= */ 256,
                  /* firstSegmentOffset= */ 0))
          .isNotNull();
    }
  }

  @Test
  public void aesCtrHmacStreamingAeadCreate() throws Exception {
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.create(
            createAesCtrHmacParameters(),
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()));
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesCtrHmacStreamingAead.create(key));
    } else {
      assertThat(AesCtrHmacStreamingAead.create(key)).isNotNull();
    }
  }

  @Test
  public void aesGcmHkdfStreamingAeadCreate() throws Exception {
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.create(
            createAesGcmHkdfParameters(),
            SecretBytes.copyFrom(new byte[32], InsecureSecretKeyAccess.get()));
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> AesGcmHkdfStreamingAead.create(key));
    } else {
      assertThat(AesGcmHkdfStreamingAead.create(key)).isNotNull();
    }
  }
}
