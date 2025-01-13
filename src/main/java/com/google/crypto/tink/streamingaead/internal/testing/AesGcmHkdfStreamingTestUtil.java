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

  public static StreamingAeadTestVector[] createAesGcmHkdfTestVectors() {
    return exceptionIsBug(
        () ->
            new StreamingAeadTestVector[] {
              createTestVector0(),
            });
  }

  private AesGcmHkdfStreamingTestUtil() {}
}
