// Copyright 2023 Google LLC
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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.keyderivation.internal.test.PrfBasedKeyDeriverTestVectors;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * Another test class for PrfBasedDeriver. We use a different class because we want to use the
 * Keyset API and do not want to touch the protos. This means that the includes here are the normal
 * classes and not the protos -- which means that all the includes would clash and we would have to
 * extend either the proto or the java AesGcmKey -- for example, if we put it in the same file.
 *
 * <p>Hence we make a different file.
 *
 * <p>The tests here should cover everything, but the previous test also checks some behavior of the
 * internal API (which will be removed). Once the internal API is removed we can remove the other
 * tests as well.
 */
@RunWith(Theories.class)
public final class PrfBasedDeriverSecondTest {

  @BeforeClass
  public static void registerAll() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
    TinkConfig.register();
    KeyDerivationConfig.register();
    JwtSignatureConfig.register();
    JwtMacConfig.register();
  }

  @Test
  public void basicTest() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey).withFixedId(123).makePrimary())
            .build();

    KeysetDeriver deriver = keyset.getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(new byte[] {1});
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(derivedKeyParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("4A8984211468FF8B78399156F0989A31"), InsecureSecretKeyAccess.get()))
            .build();

    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getAt(0).getId()).isEqualTo(123);
    assertThat(derivedKeyset.getAt(0).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(derivedKeyParameters);
    assertThat(derivedKeyset.getAt(0).getKey().equalsKey(expectedKey)).isTrue();
  }


  /* Some PrfBasedKeyDerivationKey. */
  private static PrfBasedKeyDerivationKey getPrfBasedKeyDerivationKey0()
      throws GeneralSecurityException {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    return PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);
  }

  /* Some other PrfBasedKeyDerivationKey -- needs ID = 557 */
  private static PrfBasedKeyDerivationKey getPrfBasedKeyDerivationKey1()
      throws GeneralSecurityException {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("1111111111111111111111111111111111111111111111111111111111111111"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    return PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 557);
  }

  /* A third key -- needs ID = 555 */
  private static PrfBasedKeyDerivationKey getPrfBasedKeyDerivationKey2()
      throws GeneralSecurityException {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("2222222222222222222222222222222222222222222222222222222222222200"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    return PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ 555);
  }

  @Test
  public void testWithMultipleKeys() throws Exception {
    PrfBasedKeyDerivationKey keyDerivationKey0 = getPrfBasedKeyDerivationKey0();
    PrfBasedKeyDerivationKey keyDerivationKey1 = getPrfBasedKeyDerivationKey1();
    PrfBasedKeyDerivationKey keyDerivationKey2 = getPrfBasedKeyDerivationKey2();

    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey0).withFixedId(558))
            .addEntry(KeysetHandle.importKey(keyDerivationKey1).withFixedId(557).makePrimary())
            .addEntry(KeysetHandle.importKey(keyDerivationKey2).withFixedId(555))
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class);
    KeysetHandle derivedKeyset = deriver.deriveKeyset(new byte[] {1, 0, 1});

    Key expectedKey0 =
        AesGcmKey.builder()
            .setParameters(
                (AesGcmParameters) keyDerivationKey0.getParameters().getDerivedKeyParameters())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("714ee0b48237680103f7712fb02f8008"), InsecureSecretKeyAccess.get()))
            .build();
    Key expectedKey1 =
        AesGcmKey.builder()
            .setParameters(
                (AesGcmParameters) keyDerivationKey1.getParameters().getDerivedKeyParameters())
            .setIdRequirement(557)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("1245823cad59902bc88804d1ad53d251"), InsecureSecretKeyAccess.get()))
            .build();
    Key expectedKey2 =
        AesGcmKey.builder()
            .setParameters(
                (AesGcmParameters) keyDerivationKey2.getParameters().getDerivedKeyParameters())
            .setIdRequirement(555)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("b172d3bb44346382f48e480b061c5624"), InsecureSecretKeyAccess.get()))
            .build();

    KeysetHandle expectedKeyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(expectedKey0).withFixedId(558))
            .addEntry(KeysetHandle.importKey(expectedKey1).withFixedId(557).makePrimary())
            .addEntry(KeysetHandle.importKey(expectedKey2).withFixedId(555))
            .build();

    assertThat(derivedKeyset.equalsKeyset(expectedKeyset)).isTrue();
  }

  @DataPoints("allTests")
  public static final PrfBasedKeyDeriverTestVectors.TestVector[] allTestVectors =
      exceptionIsBug(PrfBasedKeyDeriverTestVectors::createTestVectors);

  @Theory
  public void deriveKeyset_isAsExpected(
      @FromDataPoints("allTests") PrfBasedKeyDeriverTestVectors.TestVector t) throws Exception {
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(t.prfKey.getParameters())
            .build();

    @Nullable Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);
    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(keyDerivationKey)
                    .withFixedId(idRequirement == null ? 789789 : idRequirement)
                    .makePrimary())
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode(t.inputHex));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(t.derivedKeyParameters);
    assertThat(derivedKeyset.getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(idRequirement);
    assertTrue(derivedKeyset.getAt(0).getKey().equalsKey(t.expectedKey));
  }

  @Test
  public void deriveAesGcmSivKey_isAsExpected() throws Exception {
    Assume.assumeTrue(Conscrypt.isAvailable());

    PrfBasedKeyDeriverTestVectors.TestVector t =
        PrfBasedKeyDeriverTestVectors.createAesGcmSivTestVector();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(t.prfKey.getParameters())
            .build();

    @Nullable Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);
    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(keyDerivationKey)
                    .withFixedId(idRequirement == null ? 789789 : idRequirement)
                    .makePrimary())
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode(t.inputHex));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(t.derivedKeyParameters);
    assertThat(derivedKeyset.getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(idRequirement);
    assertTrue(derivedKeyset.getAt(0).getKey().equalsKey(t.expectedKey));
  }
}
