// Copyright 2020 Google LLC
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
package com.google.crypto.tink.prf.subtle;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.subtle.Hkdf;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@link HkdfPrf}. Note that these tests rely on the tests for HkdfStreamingPrfTest to
 * vet the cryptographic gaurantees of Tink's PRF implementation. This class only tests the
 * differences with Prf.
 */
@RunWith(JUnit4.class)
@LowLevelCryptoCaller
public class HkdfPrfTest {

  private static Prf createHkdfPrf(HashType hashType, byte[] ikm, byte[] salt)
      throws GeneralSecurityException {
    HkdfPrfParameters.HashType paramHashType;
    switch (hashType) {
      case SHA1:
        paramHashType = HkdfPrfParameters.HashType.SHA1;
        break;
      case SHA224:
        paramHashType = HkdfPrfParameters.HashType.SHA224;
        break;
      case SHA256:
        paramHashType = HkdfPrfParameters.HashType.SHA256;
        break;
      case SHA384:
        paramHashType = HkdfPrfParameters.HashType.SHA384;
        break;
      case SHA512:
        paramHashType = HkdfPrfParameters.HashType.SHA512;
        break;
      default:
        throw new IllegalArgumentException("Unknown hash type: " + hashType);
    }
    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setHashType(paramHashType)
                    .setKeySizeBytes(ikm.length)
                    .setSalt(Bytes.copyFrom(salt))
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(ikm, InsecureSecretKeyAccess.get()))
            .build();
    return HkdfPrf.create(key);
  }

  @Test
  public void testComputePrf_returnsExpectedSize() throws Exception {
    Prf prf =
        createHkdfPrf(HashType.SHA1, "key0123456789012345".getBytes(UTF_8), "salt".getBytes(UTF_8));

    byte[] out = prf.compute("input".getBytes(UTF_8), 12);

    assertThat(out).hasLength(12);
  }

  @Test
  public void computePrf_returnsExpectedValue() throws Exception {
    byte[] secret = Random.randBytes(32);
    byte[] salt = Random.randBytes(5);
    byte[] info = "cloudSharingId".getBytes(UTF_8);
    int outputSize = 32;
    byte[] expected =
        Hkdf.computeHkdf(
            /* macAlgorithm= */ "HMACSHA256",
            /* ikm= */ secret,
            /* salt= */ salt,
            /* info= */ info,
            /* size= */ outputSize);

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .setKeySizeBytes(secret.length)
                    .setSalt(Bytes.copyFrom(salt))
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(secret, InsecureSecretKeyAccess.get()))
            .build();
    Prf prf = HkdfPrf.create(key);

    byte[] output = prf.compute(info, outputSize);

    assertThat(output).isEqualTo(expected);
  }


  @Test
  public void computePrfWithoutSalt_returnsExpectedValue() throws Exception {
    byte[] secret = Random.randBytes(32);
    byte[] info = "cloudSharingId".getBytes(UTF_8);
    int outputSize = 32;
    byte[] expected =
        Hkdf.computeHkdf(
            /* macAlgorithm= */ "HMACSHA256",
            /* ikm= */ secret,
            /* salt= */ null,
            /* info= */ info,
            /* size= */ outputSize);

    HkdfPrfKey key =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .setSalt(Bytes.copyFrom(new byte[0]))
                    .setKeySizeBytes(secret.length)
                    .build())
            .setKeyBytes(SecretBytes.copyFrom(secret, InsecureSecretKeyAccess.get()))
            .build();
    Prf prf = HkdfPrf.create(key);

    byte[] output = prf.compute(info, outputSize);

    assertThat(output).isEqualTo(expected);
  }

  @Test
  public void testComputePrf_consistentPrefix() throws Exception {
    Prf prf =
        createHkdfPrf(HashType.SHA1, "key0123456789012345".getBytes(UTF_8), "salt".getBytes(UTF_8));

    byte[] out = prf.compute("input".getBytes(UTF_8), 12);
    byte[] outLonger = prf.compute("input".getBytes(UTF_8), 16);
    byte[] outTruncated = Arrays.copyOf(outLonger, 12);

    assertThat(out).hasLength(12);
    assertArrayEquals(out, outTruncated);
  }

  @Test
  public void testComputePrf_enforcesParameterConstraints() throws Exception {
    Prf prf =
        createHkdfPrf(HashType.SHA1, "key0123456789012345".getBytes(UTF_8), "salt".getBytes(UTF_8));

    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute(null, 6);
          }
        });
    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute("input".getBytes(UTF_8), -1);
          }
        });
    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute("input".getBytes(UTF_8), 0);
          }
        });
  }
}
