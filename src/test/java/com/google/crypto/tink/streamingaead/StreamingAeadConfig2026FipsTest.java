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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link StreamingAeadConfig2026} which run under FIPS mode.
 *
 * <p>We test this by tagging the test with "fips" which runs it under three build configurations:
 *
 * <ul>
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=False}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *   <li>{@code
 *       //third_party/tink/java_src/src/main/java/com/google/crypto/tink/config:use_only_fips=True}
 *       and {@code BORINGSSL_FIPS=0} in C++
 * </ul>
 *
 * <p>Since {@link StreamingAeadConfig2026} contains no FIPS-compliant algorithms, in FIPS mode
 * {@code StreamingAeadConfig2026.get()} returns an empty configuration rather than throwing an
 * exception. Unlike full FIPS tests (e.g. {@code AeadConfig2026FipsTest} or {@code
 * MacConfig2026FipsTest}), we only need to test this basic behavior here.
 */
@RunWith(JUnit4.class)
public final class StreamingAeadConfig2026FipsTest {

  @Test
  public void get_returnsEmptyConfigurationInFipsMode() throws Exception {
    assertThat(StreamingAeadConfig2026.get()).isNotNull();
    if (!TinkFipsUtil.useOnlyFips()) {
      return;
    }

    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(32)
            .setDerivedAesGcmKeySizeBytes(32)
            .setCiphertextSegmentSizeBytes(100)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(parameters, StreamingAeadConfig2026.get()));
  }
}
