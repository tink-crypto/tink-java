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

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.EciesPrivateKey;
import com.google.crypto.tink.hybrid.PredefinedHybridParameters;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link EciesKeyCreator}. */
@RunWith(JUnit4.class)
public final class EciesKeyCreatorTest {

  @Test
  public void createKey_p256_works() throws Exception {
    EciesParameters parameters = PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    EciesPrivateKey key = EciesKeyCreator.createKey(parameters, /* idRequirement= */ 123);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(123);
    assertThat(key.getOutputPrefix()).isNotNull();
    assertThat(key.getPublicKey().getNistCurvePoint()).isNotNull();
    assertThat(key.getNistPrivateKeyValue()).isNotNull();
  }

  @Test
  public void createKey_p256_raw_works() throws Exception {
    EciesParameters parameters =
        PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX;
    EciesPrivateKey key = EciesKeyCreator.createKey(parameters, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isNull();
    assertThat(key.getPublicKey().getNistCurvePoint()).isNotNull();
    assertThat(key.getNistPrivateKeyValue()).isNotNull();
  }

  @Test
  public void createKey_p384_works() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P384)
            .setHashType(EciesParameters.HashType.SHA384)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    EciesPrivateKey key = EciesKeyCreator.createKey(parameters, /* idRequirement= */ 456);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(456);
    assertThat(key.getPublicKey().getNistCurvePoint()).isNotNull();
    assertThat(key.getNistPrivateKeyValue()).isNotNull();
  }

  @Test
  public void createKey_p521_works() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P521)
            .setHashType(EciesParameters.HashType.SHA512)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    EciesPrivateKey key = EciesKeyCreator.createKey(parameters, /* idRequirement= */ 789);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getIdRequirementOrNull()).isEqualTo(789);
    assertThat(key.getPublicKey().getNistCurvePoint()).isNotNull();
    assertThat(key.getNistPrivateKeyValue()).isNotNull();
  }

  @Test
  public void createKey_unsupportedCurveType_throws() throws Exception {
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> EciesKeyCreator.createKey(parameters, /* idRequirement= */ null));
  }

  @Test
  public void createKey_calledTwice_createsDifferentKeys() throws Exception {
    int numKeys = 2;
    EciesParameters parameters = PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      EciesPrivateKey key = EciesKeyCreator.createKey(parameters, /* idRequirement= */ 123);
      keys.add(key.getNistPrivateKeyValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }
}
