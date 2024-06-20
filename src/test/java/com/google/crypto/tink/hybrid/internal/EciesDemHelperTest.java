// Copyright 2024 Google LLC
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

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.internal.testing.EciesAeadHkdfTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link EciesDemHelper}. */
@RunWith(Theories.class)
public final class EciesDemHelperTest {

  @Before
  public void doBeforeEachTest() throws Exception {
    AeadConfig.register();
  }

  private static Parameters[] validDemParameters() throws GeneralSecurityException {
    return new Parameters[] {
      // AES128_GCM_RAW
      AesGcmParameters.builder()
          .setIvSizeBytes(12)
          .setKeySizeBytes(16)
          .setTagSizeBytes(16)
          .setVariant(AesGcmParameters.Variant.NO_PREFIX)
          .build(),
      // AES256_GCM_RAW
      AesGcmParameters.builder()
          .setIvSizeBytes(12)
          .setKeySizeBytes(32)
          .setTagSizeBytes(16)
          .setVariant(AesGcmParameters.Variant.NO_PREFIX)
          .build(),
      // AES128_CTR_HMAC_SHA256_RAW
      AesCtrHmacAeadParameters.builder()
          .setAesKeySizeBytes(16)
          .setHmacKeySizeBytes(32)
          .setTagSizeBytes(16)
          .setIvSizeBytes(16)
          .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
          .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
          .build(),
      // AES256_CTR_HMAC_SHA256_RAW
      AesCtrHmacAeadParameters.builder()
          .setAesKeySizeBytes(32)
          .setHmacKeySizeBytes(32)
          .setTagSizeBytes(32)
          .setIvSizeBytes(16)
          .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
          .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
          .build(),
      // AES256_SIV_RAW
      AesSivParameters.builder()
          .setKeySizeBytes(64)
          .setVariant(AesSivParameters.Variant.NO_PREFIX)
          .build()
    };
  }

  @DataPoints("dem_parameters")
  public static final Parameters[] demParameters = exceptionIsBug(() -> validDemParameters());

  @Theory
  public void encryptDecrypt(@FromDataPoints("dem_parameters") Parameters demParameters)
      throws GeneralSecurityException {
    EciesParameters parameters =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(demParameters)
            .build();
    EciesDemHelper.Dem dem = EciesDemHelper.getDem(parameters);

    assertThat(dem.getSymmetricKeySizeInBytes()).isGreaterThan(15);
    assertThat(dem.getSymmetricKeySizeInBytes()).isLessThan(65);

    byte[] demKeyValue = Random.randBytes(dem.getSymmetricKeySizeInBytes());
    byte[] prefix = Random.randBytes(10);
    byte[] header = Random.randBytes(20);
    byte[] plaintext = Random.randBytes(100);

    byte[] ciphertext = dem.encrypt(demKeyValue, prefix, header, plaintext);

    assertThat(Arrays.copyOf(ciphertext, prefix.length)).isEqualTo(prefix);
    assertThat(Arrays.copyOfRange(ciphertext, prefix.length, prefix.length + header.length))
        .isEqualTo(header);

    byte[] decrypted = dem.decrypt(demKeyValue, ciphertext, prefix.length + header.length);
    assertThat(decrypted).isEqualTo(plaintext);

    // Different demKeyValue fails
    assertThrows(
        GeneralSecurityException.class,
        () ->
            dem.decrypt(
                Random.randBytes(dem.getSymmetricKeySizeInBytes()),
                ciphertext,
                prefix.length + header.length));

    // Fails when ciphertext is modified.
    ciphertext[ciphertext.length - 1] ^= 1;
    assertThrows(
        GeneralSecurityException.class,
        () -> dem.decrypt(demKeyValue, ciphertext, prefix.length + header.length));

    // Fails when ciphertext is too short.
    assertThrows(
        GeneralSecurityException.class,
        () -> dem.decrypt(demKeyValue, new byte[0], prefix.length + header.length));
  }

  @DataPoints("testVectors")
  public static final HybridTestVector[] TEST_VECTORS =
      EciesAeadHkdfTestUtil.createEciesTestVectors();

  @Theory
  public void test_decryptCiphertext_works(@FromDataPoints("testVectors") HybridTestVector v)
      throws GeneralSecurityException {
    EciesParameters parameters = (EciesParameters) v.getPrivateKey().getParameters();
    EciesDemHelper.Dem dem = EciesDemHelper.getDem(parameters);
    assertThat(dem.getSymmetricKeySizeInBytes()).isEqualTo(v.getSymmetricKey().length);
    byte[] decrypted =
        dem.decrypt(
            v.getSymmetricKey(), v.getCiphertext(), v.getPrefixLength() + v.getHeaderLength());
    assertThat(Hex.encode(decrypted)).isEqualTo(Hex.encode(v.getPlaintext()));
  }
}
