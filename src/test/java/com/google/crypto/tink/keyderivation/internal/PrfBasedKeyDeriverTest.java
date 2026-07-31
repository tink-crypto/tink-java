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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.keyderivation.internal.test.PrfBasedKeyDeriverTestVectors;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
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
public final class PrfBasedKeyDeriverTest {

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

    @SuppressWarnings("Immutable") // b/540692422
    KeyDeriver deriver =
        PrfBasedKeyDeriver.create(
            k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
            MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
            keyDerivationKey);

    Key derivedKey = deriver.deriveKey(new byte[] {1});
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(derivedKeyParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("4A8984211468FF8B78399156F0989A31"), InsecureSecretKeyAccess.get()))
            .build();

    assertThat(derivedKey.getParameters()).isEqualTo(derivedKeyParameters);
    assertThat(derivedKey.equalsKey(expectedKey)).isTrue();
  }

  @Test
  @SuppressWarnings("Immutable") // b/540692422
  public void create_prfKeyHasNoStreamingPrf_throws() throws Exception {
    PrfParameters prfParameters =
        new PrfParameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    // We create an ad-hoc subclass of "PrfKey". For this one, it is not possible that a map
    // (Anonymous subclass) -> StreamingPrf was registered, since the subclass cannot be referenced
    // from anywhere.
    PrfKey prfKey =
        new PrfKey() {
          @Override
          public PrfParameters getParameters() {
            return prfParameters;
          }

          @Override
          public boolean equalsKey(Key key) {
            return key == this;
          }

          @Override
          public Integer getIdRequirementOrNull() {
            return null;
          }
        };
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
            .setPrfParameters(prfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDeriver.create(
                k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
                MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
                keyDerivationKey));
  }

  @Test
  @SuppressWarnings("Immutable") // b/540692422
  public void create_derivedParametersHasNoKeyDerivationFactory_throws() throws Exception {
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
    Parameters derivedKeyParameters =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDeriver.create(
                k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
                MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
                keyDerivationKey));
  }

  @DataPoints("allTests")
  public static final PrfBasedKeyDeriverTestVectors.TestVector[] allTestVectors =
      exceptionIsBug(PrfBasedKeyDeriverTestVectors::createTestVectors);

  @Theory
  @SuppressWarnings("Immutable") // b/540692422
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
    KeyDeriver deriver =
        PrfBasedKeyDeriver.create(
            k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
            MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
            keyDerivationKey);

    Key derivedKey = deriver.deriveKey(Hex.decode(t.inputHex));

    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKey.getParameters()).isEqualTo(t.derivedKeyParameters);
    assertTrue(derivedKey.equalsKey(t.expectedKey));
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
    // The PrfBasedKeyDeriver was annotated with @Immutable when the offending call happened in
    // the deriver itself, which the error prone checker did not catch. Since my are anyhow moving
    // to an Immutable class I don't want to change this.
    @SuppressWarnings("Immutable")
    KeyDeriver deriver =
        PrfBasedKeyDeriver.create(
            k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
            MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
            keyDerivationKey);

    Key derivedKey = deriver.deriveKey(Hex.decode(t.inputHex));

    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKey.getParameters()).isEqualTo(t.derivedKeyParameters);
    assertTrue(derivedKey.equalsKey(t.expectedKey));
  }

  @Immutable
  private static final class TestStreamingPrf implements StreamingPrf {

    @Override
    public InputStream computePrf(byte[] input) {
      return new ByteArrayInputStream(new byte[64]);
    }

    TestStreamingPrf(HkdfPrfKey prfKey) {}
  }

  @Theory
  @SuppressWarnings("Immutable") // b/540692422
  public void createWithPrfPrimitiveRegistry_works(
      @FromDataPoints("allTests") PrfBasedKeyDeriverTestVectors.TestVector t) throws Exception {
    PrimitiveRegistry prfRegistry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    TestStreamingPrf::new, HkdfPrfKey.class, StreamingPrf.class))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(t.prfKey.getParameters())
            .build();
    @Nullable Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);

    assertThat(
            PrfBasedKeyDeriver.create(
                k -> prfRegistry.getPrimitive(k, StreamingPrf.class),
                MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
                keyDerivationKey))
        .isNotNull();
  }

  @Test
  @SuppressWarnings("Immutable") // b/540692422
  public void createWithPrfPrimitiveRegistry_wrongRegistryThrows() throws Exception {
    PrimitiveRegistry wrongRegistry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(AesGcmJce::create, AesGcmKey.class, Aead.class))
            .build();
    PrfBasedKeyDeriverTestVectors.TestVector t = allTestVectors[0];
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(t.prfKey.getParameters())
            .build();
    @Nullable Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDeriver.create(
                k -> wrongRegistry.getPrimitive(k, StreamingPrf.class),
                MutableKeyDerivationRegistry.globalInstance()::createKeyFromRandomness,
                keyDerivationKey));
  }

  @AccessesPartialKey
  private static Key createKeyFromRandomnessForAesGcm(
      Parameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!(parameters instanceof AesGcmParameters)) {
      throw new GeneralSecurityException("Expected AesGcmParameters");
    }
    AesGcmParameters aesGcmParameters = (AesGcmParameters) parameters;
    return AesGcmKey.builder()
        .setParameters(aesGcmParameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, aesGcmParameters.getKeySizeBytes(), access))
        .build();
  }

  @Test
  public void create_usesKeyFromRandomness() throws Exception {
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

    KeyDeriver deriver =
        PrfBasedKeyDeriver.create(
            k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
            PrfBasedKeyDeriverTest::createKeyFromRandomnessForAesGcm,
            keyDerivationKey);

    Key derivedKey = deriver.deriveKey(new byte[] {1});
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(derivedKeyParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("4A8984211468FF8B78399156F0989A31"), InsecureSecretKeyAccess.get()))
            .build();

    assertThat(derivedKey.getParameters()).isEqualTo(derivedKeyParameters);
    assertThat(derivedKey.equalsKey(expectedKey)).isTrue();
  }

  @Test
  public void create_keyFromRandomnessForAesGcm_nonAesGcmParameters_throws() throws Exception {
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
    Parameters nonAesGcmParameters = XChaCha20Poly1305Parameters.create();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(nonAesGcmParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrfBasedKeyDeriver.create(
                k -> MutablePrimitiveRegistry.globalInstance().getPrimitive(k, StreamingPrf.class),
                PrfBasedKeyDeriverTest::createKeyFromRandomnessForAesGcm,
                keyDerivationKey));
  }
}
