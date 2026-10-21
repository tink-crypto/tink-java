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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.jwt.internal.JwtEcdsaKeyCreator;
import com.google.crypto.tink.jwt.internal.JwtMlDsaKeyCreator;
import com.google.crypto.tink.jwt.internal.JwtRsaSsaPkcs1KeyCreator;
import com.google.crypto.tink.jwt.internal.JwtRsaSsaPssKeyCreator;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtEcdsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtHmac;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtMlDsaPublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPkcs1PublicKeyVerify;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeySign;
import com.google.crypto.tink.jwt.subtle.JwtRsaSsaPssPublicKeyVerify;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for JWT which run under FIPS mode.
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
 *       and {@code BORINGSSL_FIPS=0} in C++.
 * </ul>
 */
@RunWith(JUnit4.class)
public final class FipsTest {

  @BeforeClass
  public static void setUp() {
    if (!TestUtil.isAndroid()) {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void jwtConfig2026_hmac() throws Exception {
    JwtHmacParameters hmacParams =
        JwtHmacParameters.builder()
            .setKeySizeBytes(32)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .build();
    JwtHmacKey hmacKey =
        JwtHmacKey.builder()
            .setParameters(hmacParams)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    KeysetHandle hmacHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hmacKey).withRandomId().makePrimary())
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(hmacParams, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> hmacHandle.getPrimitive(JwtConfig2026.get(), JwtMac.class));
    } else {
      assertThat(KeysetHandle.generateNew(hmacParams, JwtConfig2026.get())).isNotNull();
      assertThat(hmacHandle.getPrimitive(JwtConfig2026.get(), JwtMac.class)).isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_ecdsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    EcdsaPrivateKey rawEcdsaPrivateKey =
        (EcdsaPrivateKey) EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey();
    JwtEcdsaParameters ecdsaParams =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey ecdsaPublicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(ecdsaParams)
            .setPublicPoint(rawEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    JwtEcdsaPrivateKey ecdsaPrivateKey =
        JwtEcdsaPrivateKey.create(ecdsaPublicKey, rawEcdsaPrivateKey);
    KeysetHandle ecdsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(ecdsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle ecdsaPublicHandle = ecdsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ecdsaParams, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> ecdsaPrivateHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> ecdsaPublicHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(ecdsaParams, JwtConfig2026.get())).isNotNull();
      assertThat(ecdsaPrivateHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(ecdsaPublicHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_rsaSsaPkcs1_2048() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1PrivateKey rawRsaPkcs1PrivateKey2048 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey();
    JwtRsaSsaPkcs1Parameters rsaPkcs1Params2048 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey rsaPkcs1PublicKey2048 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(rsaPkcs1Params2048)
            .setModulus(rawRsaPkcs1PrivateKey2048.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPkcs1PrivateKey rsaPkcs1PrivateKey2048 =
        JwtRsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(rsaPkcs1PublicKey2048)
            .setRsaSsaPkcs1PrivateKey(rawRsaPkcs1PrivateKey2048)
            .build();
    KeysetHandle rsaPkcs1PrivateHandle2048 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPkcs1PrivateKey2048).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPkcs1PublicHandle2048 = rsaPkcs1PrivateHandle2048.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPkcs1Params2048, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PrivateHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PublicHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPkcs1Params2048, JwtConfig2026.get())).isNotNull();
      assertThat(
              rsaPkcs1PrivateHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPkcs1PublicHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_rsaSsaPkcs1_4096() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1PrivateKey rawRsaPkcs1PrivateKey4096 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[5].getPrivateKey();
    JwtRsaSsaPkcs1Parameters rsaPkcs1Params4096 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey rsaPkcs1PublicKey4096 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(rsaPkcs1Params4096)
            .setModulus(rawRsaPkcs1PrivateKey4096.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPkcs1PrivateKey rsaPkcs1PrivateKey4096 =
        JwtRsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(rsaPkcs1PublicKey4096)
            .setRsaSsaPkcs1PrivateKey(rawRsaPkcs1PrivateKey4096)
            .build();
    KeysetHandle rsaPkcs1PrivateHandle4096 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPkcs1PrivateKey4096).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPkcs1PublicHandle4096 = rsaPkcs1PrivateHandle4096.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPkcs1Params4096, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PrivateHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PublicHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPkcs1Params4096, JwtConfig2026.get())).isNotNull();
      assertThat(
              rsaPkcs1PrivateHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPkcs1PublicHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_rsaSsaPss_2048() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssPrivateKey rawRsaPssPrivateKey2048 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey();
    JwtRsaSsaPssParameters rsaPssParams2048 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey rsaPssPublicKey2048 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(rsaPssParams2048)
            .setModulus(rawRsaPssPrivateKey2048.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPssPrivateKey rsaPssPrivateKey2048 =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(rsaPssPublicKey2048)
            .setRsaSsaPssPrivateKey(rawRsaPssPrivateKey2048)
            .build();
    KeysetHandle rsaPssPrivateHandle2048 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPssPrivateKey2048).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPssPublicHandle2048 = rsaPssPrivateHandle2048.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPssParams2048, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> rsaPssPrivateHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> rsaPssPublicHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPssParams2048, JwtConfig2026.get())).isNotNull();
      assertThat(rsaPssPrivateHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(rsaPssPublicHandle2048.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_rsaSsaPss_4096() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssPrivateKey rawRsaPssPrivateKey4096 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[6].getPrivateKey();
    JwtRsaSsaPssParameters rsaPssParams4096 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey rsaPssPublicKey4096 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(rsaPssParams4096)
            .setModulus(rawRsaPssPrivateKey4096.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPssPrivateKey rsaPssPrivateKey4096 =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(rsaPssPublicKey4096)
            .setRsaSsaPssPrivateKey(rawRsaPssPrivateKey4096)
            .build();
    KeysetHandle rsaPssPrivateHandle4096 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPssPrivateKey4096).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPssPublicHandle4096 = rsaPssPrivateHandle4096.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPssParams4096, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> rsaPssPrivateHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> rsaPssPublicHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPssParams4096, JwtConfig2026.get())).isNotNull();
      assertThat(rsaPssPrivateHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(rsaPssPublicHandle4096.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtConfig2026_mlDsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    MlDsaPrivateKey rawMlDsaPrivateKey =
        (MlDsaPrivateKey)
            MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                    MlDsaParameters.create(
                        MlDsaParameters.MlDsaInstance.ML_DSA_65,
                        MlDsaParameters.Variant.NO_PREFIX))
                .getPrivateKey();
    JwtMlDsaParameters mlDsaParams =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);
    JwtMlDsaPublicKey mlDsaPublicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(mlDsaParams)
            .setPublicKeyBytes(rawMlDsaPrivateKey.getPublicKey().getSerializedPublicKey())
            .build();
    JwtMlDsaPrivateKey mlDsaPrivateKey =
        JwtMlDsaPrivateKey.create(mlDsaPublicKey, rawMlDsaPrivateKey);
    KeysetHandle mlDsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(mlDsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle mlDsaPublicHandle = mlDsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(mlDsaParams, JwtConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> mlDsaPrivateHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> mlDsaPublicHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(mlDsaParams, JwtConfig2026.get())).isNotNull();
      assertThat(mlDsaPrivateHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeySign.class))
          .isNotNull();
      assertThat(mlDsaPublicHandle.getPrimitive(JwtConfig2026.get(), JwtPublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void jwtHmacCreate() throws Exception {
    JwtHmacParameters hmacParams =
        JwtHmacParameters.builder()
            .setKeySizeBytes(32)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .build();
    JwtHmacKey hmacKey =
        JwtHmacKey.builder()
            .setParameters(hmacParams)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> JwtHmac.create(hmacKey));
    } else {
      assertThat(JwtHmac.create(hmacKey)).isNotNull();
    }
  }

  @Test
  public void jwtEcdsaPublicKeySignAndVerifyCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    EcdsaPrivateKey rawEcdsaPrivateKey =
        (EcdsaPrivateKey) EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey();
    JwtEcdsaParameters ecdsaParams =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey publicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(ecdsaParams)
            .setPublicPoint(rawEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    JwtEcdsaPrivateKey privateKey = JwtEcdsaPrivateKey.create(publicKey, rawEcdsaPrivateKey);
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> JwtEcdsaPublicKeySign.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> JwtEcdsaPublicKeyVerify.create(publicKey));
    } else {
      assertThat(JwtEcdsaPublicKeySign.create(privateKey)).isNotNull();
      assertThat(JwtEcdsaPublicKeyVerify.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void jwtEcdsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    JwtEcdsaParameters paramsEs256 =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaParameters paramsEs384 =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
            .build();
    JwtEcdsaParameters paramsEs512 =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .build();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class, () -> JwtEcdsaKeyCreator.createKey(paramsEs256, 123));
      assertThrows(
          GeneralSecurityException.class, () -> JwtEcdsaKeyCreator.createKey(paramsEs384, 456));
      assertThrows(
          GeneralSecurityException.class, () -> JwtEcdsaKeyCreator.createKey(paramsEs512, 789));
    } else {
      assertThat(JwtEcdsaKeyCreator.createKey(paramsEs256, 123)).isNotNull();
      assertThat(JwtEcdsaKeyCreator.createKey(paramsEs384, 456)).isNotNull();
      assertThat(JwtEcdsaKeyCreator.createKey(paramsEs512, 789)).isNotNull();
    }
  }

  @Test
  public void jwtRsaSsaPkcs1PublicKeySignAndVerifyCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1PrivateKey rawPrivateKey2048 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey();
    JwtRsaSsaPkcs1Parameters params2048 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey2048 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(params2048)
            .setModulus(rawPrivateKey2048.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey2048 =
        JwtRsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(publicKey2048)
            .setRsaSsaPkcs1PrivateKey(rawPrivateKey2048)
            .build();

    RsaSsaPkcs1PrivateKey rawPrivateKey4096 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[5].getPrivateKey();
    JwtRsaSsaPkcs1Parameters params4096 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1PublicKey publicKey4096 =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(params4096)
            .setModulus(rawPrivateKey4096.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPkcs1PrivateKey privateKey4096 =
        JwtRsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(publicKey4096)
            .setRsaSsaPkcs1PrivateKey(rawPrivateKey4096)
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1PublicKeySign.create(privateKey2048));
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1PublicKeyVerify.create(publicKey2048));
    } else {
      assertThat(JwtRsaSsaPkcs1PublicKeySign.create(privateKey2048)).isNotNull();
      assertThat(JwtRsaSsaPkcs1PublicKeyVerify.create(publicKey2048)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1PublicKeySign.create(privateKey4096));
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1PublicKeyVerify.create(publicKey4096));
    } else {
      assertThat(JwtRsaSsaPkcs1PublicKeySign.create(privateKey4096)).isNotNull();
      assertThat(JwtRsaSsaPkcs1PublicKeyVerify.create(publicKey4096)).isNotNull();
    }
  }

  @Test
  public void jwtRsaSsaPkcs1KeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    JwtRsaSsaPkcs1Parameters params2048 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .build();
    JwtRsaSsaPkcs1Parameters params3072 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
            .build();
    JwtRsaSsaPkcs1Parameters params4096 =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1KeyCreator.createKey(params2048, 123));
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1KeyCreator.createKey(params3072, 456));
    } else {
      assertThat(JwtRsaSsaPkcs1KeyCreator.createKey(params2048, 123)).isNotNull();
      assertThat(JwtRsaSsaPkcs1KeyCreator.createKey(params3072, 456)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPkcs1KeyCreator.createKey(params4096, 789));
    } else {
      assertThat(JwtRsaSsaPkcs1KeyCreator.createKey(params4096, 789)).isNotNull();
    }
  }

  @Test
  public void jwtRsaSsaPssPublicKeySignAndVerifyCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssPrivateKey rawPrivateKey2048 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey();
    JwtRsaSsaPssParameters params2048 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey2048 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(params2048)
            .setModulus(rawPrivateKey2048.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPssPrivateKey privateKey2048 =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey2048)
            .setRsaSsaPssPrivateKey(rawPrivateKey2048)
            .build();

    RsaSsaPssPrivateKey rawPrivateKey4096 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[6].getPrivateKey();
    JwtRsaSsaPssParameters params4096 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssPublicKey publicKey4096 =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(params4096)
            .setModulus(rawPrivateKey4096.getPublicKey().getModulus())
            .build();
    JwtRsaSsaPssPrivateKey privateKey4096 =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(publicKey4096)
            .setRsaSsaPssPrivateKey(rawPrivateKey4096)
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class, () -> JwtRsaSsaPssPublicKeySign.create(privateKey2048));
      assertThrows(
          GeneralSecurityException.class, () -> JwtRsaSsaPssPublicKeyVerify.create(publicKey2048));
    } else {
      assertThat(JwtRsaSsaPssPublicKeySign.create(privateKey2048)).isNotNull();
      assertThat(JwtRsaSsaPssPublicKeyVerify.create(publicKey2048)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class, () -> JwtRsaSsaPssPublicKeySign.create(privateKey4096));
      assertThrows(
          GeneralSecurityException.class, () -> JwtRsaSsaPssPublicKeyVerify.create(publicKey4096));
    } else {
      assertThat(JwtRsaSsaPssPublicKeySign.create(privateKey4096)).isNotNull();
      assertThat(JwtRsaSsaPssPublicKeyVerify.create(publicKey4096)).isNotNull();
    }
  }

  @Test
  public void jwtRsaSsaPssKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    JwtRsaSsaPssParameters params2048 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .build();
    JwtRsaSsaPssParameters params3072 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
            .build();
    JwtRsaSsaPssParameters params4096 =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
            .build();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPssKeyCreator.createKey(params2048, 123));
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPssKeyCreator.createKey(params3072, 456));
    } else {
      assertThat(JwtRsaSsaPssKeyCreator.createKey(params2048, 123)).isNotNull();
      assertThat(JwtRsaSsaPssKeyCreator.createKey(params3072, 456)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> JwtRsaSsaPssKeyCreator.createKey(params4096, 789));
    } else {
      assertThat(JwtRsaSsaPssKeyCreator.createKey(params4096, 789)).isNotNull();
    }
  }

  @Test
  public void jwtMlDsaPublicKeySignAndVerifyCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    MlDsaPrivateKey rawPrivateKey =
        (MlDsaPrivateKey)
            MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                    MlDsaParameters.create(
                        MlDsaParameters.MlDsaInstance.ML_DSA_65,
                        MlDsaParameters.Variant.NO_PREFIX))
                .getPrivateKey();
    JwtMlDsaParameters params =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_65);
    JwtMlDsaPublicKey publicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(params)
            .setPublicKeyBytes(rawPrivateKey.getPublicKey().getSerializedPublicKey())
            .build();
    JwtMlDsaPrivateKey privateKey = JwtMlDsaPrivateKey.create(publicKey, rawPrivateKey);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> JwtMlDsaPublicKeySign.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> JwtMlDsaPublicKeyVerify.create(publicKey));
    } else {
      assertThat(JwtMlDsaPublicKeySign.create(privateKey)).isNotNull();
      assertThat(JwtMlDsaPublicKeyVerify.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void jwtMlDsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    JwtMlDsaParameters params =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_65);
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> JwtMlDsaKeyCreator.createKey(params, 123));
    } else {
      assertThat(JwtMlDsaKeyCreator.createKey(params, 123)).isNotNull();
    }
  }
}
