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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.internal.CompositeMlDsaKeyCreator;
import com.google.crypto.tink.signature.internal.EcdsaKeyCreator;
import com.google.crypto.tink.signature.internal.Ed25519KeyCreator;
import com.google.crypto.tink.signature.internal.MlDsaKeyCreator;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1KeyCreator;
import com.google.crypto.tink.signature.internal.RsaSsaPssKeyCreator;
import com.google.crypto.tink.signature.internal.SlhDsaKeyCreator;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SlhDsaTestUtil;
import com.google.crypto.tink.signature.subtle.CompositeMlDsaSigner;
import com.google.crypto.tink.signature.subtle.CompositeMlDsaVerifier;
import com.google.crypto.tink.signature.subtle.EcdsaSigner;
import com.google.crypto.tink.signature.subtle.EcdsaVerifier;
import com.google.crypto.tink.signature.subtle.Ed25519Signer;
import com.google.crypto.tink.signature.subtle.Ed25519Verifier;
import com.google.crypto.tink.signature.subtle.MlDsaSigner;
import com.google.crypto.tink.signature.subtle.MlDsaVerifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Signer;
import com.google.crypto.tink.signature.subtle.RsaSsaPkcs1Verifier;
import com.google.crypto.tink.signature.subtle.RsaSsaPssSigner;
import com.google.crypto.tink.signature.subtle.RsaSsaPssVerifier;
import com.google.crypto.tink.signature.subtle.SlhDsaSigner;
import com.google.crypto.tink.signature.subtle.SlhDsaVerifier;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Signature which run under FIPS mode.
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
  public void signatureConfig2026_ecdsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    EcdsaPrivateKey ecdsaPrivateKey =
        (EcdsaPrivateKey) EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey();
    EcdsaParameters ecdsaParams = ecdsaPrivateKey.getParameters();
    KeysetHandle ecdsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(ecdsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle ecdsaPublicHandle = ecdsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ecdsaParams, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> ecdsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> ecdsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(ecdsaParams, SignatureConfig2026.get())).isNotNull();
      assertThat(ecdsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(ecdsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_rsaSsaPkcs1_2048() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1PrivateKey rsaPkcs1PrivateKey2048 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey();
    RsaSsaPkcs1Parameters rsaPkcs1Params2048 = rsaPkcs1PrivateKey2048.getParameters();
    KeysetHandle rsaPkcs1PrivateHandle2048 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPkcs1PrivateKey2048).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPkcs1PublicHandle2048 = rsaPkcs1PrivateHandle2048.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPkcs1Params2048, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PrivateHandle2048.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PublicHandle2048.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPkcs1Params2048, SignatureConfig2026.get()))
          .isNotNull();
      assertThat(
              rsaPkcs1PrivateHandle2048.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPkcs1PublicHandle2048.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_rsaSsaPkcs1_4096() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1Parameters rsaPkcs1Params4096 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey rsaPkcs1PrivateKey4096 =
        RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(rsaPkcs1Params4096, null);
    KeysetHandle rsaPkcs1PrivateHandle4096 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPkcs1PrivateKey4096).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPkcs1PublicHandle4096 = rsaPkcs1PrivateHandle4096.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPkcs1Params4096, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PrivateHandle4096.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPkcs1PublicHandle4096.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPkcs1Params4096, SignatureConfig2026.get()))
          .isNotNull();
      assertThat(
              rsaPkcs1PrivateHandle4096.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPkcs1PublicHandle4096.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_rsaSsaPss_2048() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssPrivateKey rsaPssPrivateKey2048 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey();
    RsaSsaPssParameters rsaPssParams2048 = rsaPssPrivateKey2048.getParameters();
    KeysetHandle rsaPssPrivateHandle2048 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPssPrivateKey2048).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPssPublicHandle2048 = rsaPssPrivateHandle2048.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPssParams2048, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPssPrivateHandle2048.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPssPublicHandle2048.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPssParams2048, SignatureConfig2026.get())).isNotNull();
      assertThat(
              rsaPssPrivateHandle2048.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPssPublicHandle2048.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_rsaSsaPss_4096() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssParameters rsaPssParams4096 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey rsaPssPrivateKey4096 =
        RsaSsaPssTestUtil.privateKeyFor4096BitParameters(rsaPssParams4096, null);
    KeysetHandle rsaPssPrivateHandle4096 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rsaPssPrivateKey4096).withRandomId().makePrimary())
            .build();
    KeysetHandle rsaPssPublicHandle4096 = rsaPssPrivateHandle4096.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rsaPssParams4096, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPssPrivateHandle4096.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              rsaPssPublicHandle4096.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(rsaPssParams4096, SignatureConfig2026.get())).isNotNull();
      assertThat(
              rsaPssPrivateHandle4096.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(
              rsaPssPublicHandle4096.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_ed25519() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    Ed25519PrivateKey ed25519PrivateKey =
        (Ed25519PrivateKey) Ed25519TestUtil.createTestVector0().getPrivateKey();
    Ed25519Parameters ed25519Params = ed25519PrivateKey.getParameters();
    KeysetHandle ed25519PrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(ed25519PrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle ed25519PublicHandle = ed25519PrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ed25519Params, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> ed25519PrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> ed25519PublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(ed25519Params, SignatureConfig2026.get())).isNotNull();
      assertThat(ed25519PrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(ed25519PublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_mlDsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    MlDsaParameters mlDsaParams =
        MlDsaParameters.create(
            MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);
    MlDsaPrivateKey mlDsaPrivateKey =
        (MlDsaPrivateKey)
            MlDsaTestUtil.getMlDsaValidSignatureTestVector(mlDsaParams).getPrivateKey();
    KeysetHandle mlDsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(mlDsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle mlDsaPublicHandle = mlDsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(mlDsaParams, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> mlDsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> mlDsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(mlDsaParams, SignatureConfig2026.get())).isNotNull();
      assertThat(mlDsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(mlDsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_slhDsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    SlhDsaPrivateKey slhDsaPrivateKey =
        (SlhDsaPrivateKey)
            SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors()
                .findFirst()
                .get()
                .getPrivateKey();
    SlhDsaParameters slhDsaParams = slhDsaPrivateKey.getParameters();
    KeysetHandle slhDsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(slhDsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle slhDsaPublicHandle = slhDsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(slhDsaParams, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> slhDsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () -> slhDsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(slhDsaParams, SignatureConfig2026.get())).isNotNull();
      assertThat(slhDsaPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(slhDsaPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void signatureConfig2026_compositeMlDsa() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    CompositeMlDsaPrivateKey compositeMlDsaPrivateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(
            CompositeMlDsaTestUtil.compositeMlDsaTestVectors.get(2));
    CompositeMlDsaParameters compositeMlDsaParams = compositeMlDsaPrivateKey.getParameters();
    KeysetHandle compositeMlDsaPrivateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(compositeMlDsaPrivateKey).withRandomId().makePrimary())
            .build();
    KeysetHandle compositeMlDsaPublicHandle = compositeMlDsaPrivateHandle.getPublicKeysetHandle();

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(compositeMlDsaParams, SignatureConfig2026.get()));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              compositeMlDsaPrivateHandle.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              compositeMlDsaPublicHandle.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class));
    } else {
      assertThat(KeysetHandle.generateNew(compositeMlDsaParams, SignatureConfig2026.get()))
          .isNotNull();
      assertThat(
              compositeMlDsaPrivateHandle.getPrimitive(
                  SignatureConfig2026.get(), PublicKeySign.class))
          .isNotNull();
      assertThat(
              compositeMlDsaPublicHandle.getPrimitive(
                  SignatureConfig2026.get(), PublicKeyVerify.class))
          .isNotNull();
    }
  }

  @Test
  public void ecdsaSignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    EcdsaPrivateKey privateKey =
        (EcdsaPrivateKey) EcdsaTestUtil.createEcdsaTestVectors()[0].getPrivateKey();
    EcdsaPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> EcdsaSigner.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> EcdsaVerifier.create(publicKey));
    } else {
      assertThat(EcdsaSigner.create(privateKey)).isNotNull();
      assertThat(EcdsaVerifier.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void ecdsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () ->
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P256, /* idRequirement= */ 123));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P384, /* idRequirement= */ 456));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P521, /* idRequirement= */ 789));
    } else {
      assertThat(
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P256, /* idRequirement= */ 123))
          .isNotNull();
      assertThat(
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P384, /* idRequirement= */ 456))
          .isNotNull();
      assertThat(
              EcdsaKeyCreator.createKey(
                  PredefinedSignatureParameters.ECDSA_P521, /* idRequirement= */ 789))
          .isNotNull();
    }
  }

  @Test
  public void rsaSsaPkcs1SignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1PrivateKey privateKey2048 =
        (RsaSsaPkcs1PrivateKey)
            RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0].getPrivateKey();
    RsaSsaPkcs1PublicKey publicKey2048 = privateKey2048.getPublicKey();

    RsaSsaPkcs1Parameters parameters4096 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey4096 =
        RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(parameters4096, null);
    RsaSsaPkcs1PublicKey publicKey4096 = privateKey4096.getPublicKey();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1Signer.create(privateKey2048));
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1Verifier.create(publicKey2048));
    } else {
      assertThat(RsaSsaPkcs1Signer.create(privateKey2048)).isNotNull();
      assertThat(RsaSsaPkcs1Verifier.create(publicKey2048)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1Signer.create(privateKey4096));
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1Verifier.create(publicKey4096));
    } else {
      assertThat(RsaSsaPkcs1Signer.create(privateKey4096)).isNotNull();
      assertThat(RsaSsaPkcs1Verifier.create(publicKey4096)).isNotNull();
    }
  }

  @Test
  public void rsaSsaPkcs1KeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPkcs1Parameters parameters2048 =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1Parameters parameters3072 =
        PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4;
    RsaSsaPkcs1Parameters parameters4096 =
        PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4;

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPkcs1KeyCreator.createKey(parameters2048, /* idRequirement= */ null));
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPkcs1KeyCreator.createKey(parameters3072, /* idRequirement= */ 123));
    } else {
      assertThat(RsaSsaPkcs1KeyCreator.createKey(parameters2048, /* idRequirement= */ null))
          .isNotNull();
      assertThat(RsaSsaPkcs1KeyCreator.createKey(parameters3072, /* idRequirement= */ 123))
          .isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPkcs1KeyCreator.createKey(parameters4096, /* idRequirement= */ 456));
    } else {
      assertThat(RsaSsaPkcs1KeyCreator.createKey(parameters4096, /* idRequirement= */ 456))
          .isNotNull();
    }
  }

  @Test
  public void rsaSsaPssSignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssPrivateKey privateKey2048 =
        (RsaSsaPssPrivateKey) RsaSsaPssTestUtil.createRsaPssTestVectors()[0].getPrivateKey();
    RsaSsaPssPublicKey publicKey2048 = privateKey2048.getPublicKey();

    RsaSsaPssParameters parameters4096 =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey privateKey4096 =
        RsaSsaPssTestUtil.privateKeyFor4096BitParameters(parameters4096, null);
    RsaSsaPssPublicKey publicKey4096 = privateKey4096.getPublicKey();

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSigner.create(privateKey2048));
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssVerifier.create(publicKey2048));
    } else {
      assertThat(RsaSsaPssSigner.create(privateKey2048)).isNotNull();
      assertThat(RsaSsaPssVerifier.create(publicKey2048)).isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSigner.create(privateKey4096));
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssVerifier.create(publicKey4096));
    } else {
      assertThat(RsaSsaPssSigner.create(privateKey4096)).isNotNull();
      assertThat(RsaSsaPssVerifier.create(publicKey4096)).isNotNull();
    }
  }

  @Test
  public void rsaSsaPssKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    RsaSsaPssParameters parameters2048 =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssParameters parameters3072 =
        PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4;
    RsaSsaPssParameters parameters4096 =
        PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4;

    if (TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPssKeyCreator.createKey(parameters2048, /* idRequirement= */ null));
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPssKeyCreator.createKey(parameters3072, /* idRequirement= */ 123));
    } else {
      assertThat(RsaSsaPssKeyCreator.createKey(parameters2048, /* idRequirement= */ null))
          .isNotNull();
      assertThat(RsaSsaPssKeyCreator.createKey(parameters3072, /* idRequirement= */ 123))
          .isNotNull();
    }

    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPssKeyCreator.createKey(parameters4096, /* idRequirement= */ 456));
    } else {
      assertThat(RsaSsaPssKeyCreator.createKey(parameters4096, /* idRequirement= */ 456))
          .isNotNull();
    }
  }

  @Test
  public void ed25519SignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    Ed25519PrivateKey privateKey =
        (Ed25519PrivateKey) Ed25519TestUtil.createTestVector0().getPrivateKey();
    Ed25519PublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> Ed25519Signer.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> Ed25519Verifier.create(publicKey));
    } else {
      assertThat(Ed25519Signer.create(privateKey)).isNotNull();
      assertThat(Ed25519Verifier.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void ed25519KeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () ->
              Ed25519KeyCreator.createKey(
                  PredefinedSignatureParameters.ED25519, /* idRequirement= */ 123));
    } else {
      assertThat(
              Ed25519KeyCreator.createKey(
                  PredefinedSignatureParameters.ED25519, /* idRequirement= */ 123))
          .isNotNull();
    }
  }

  @Test
  public void mlDsaSignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    MlDsaParameters parameters =
        MlDsaParameters.create(
            MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);
    MlDsaPrivateKey privateKey =
        (MlDsaPrivateKey)
            MlDsaTestUtil.getMlDsaValidSignatureTestVector(parameters).getPrivateKey();
    MlDsaPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> MlDsaSigner.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> MlDsaVerifier.create(publicKey));
    } else {
      assertThat(MlDsaSigner.create(privateKey)).isNotNull();
      assertThat(MlDsaVerifier.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void mlDsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    MlDsaParameters parameters =
        MlDsaParameters.create(
            MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK);
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
    } else {
      assertThat(MlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123)).isNotNull();
    }
  }

  @Test
  public void slhDsaSignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    SlhDsaPrivateKey privateKey =
        (SlhDsaPrivateKey)
            SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors()
                .findFirst()
                .get()
                .getPrivateKey();
    SlhDsaPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> SlhDsaSigner.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> SlhDsaVerifier.create(publicKey));
    } else {
      assertThat(SlhDsaSigner.create(privateKey)).isNotNull();
      assertThat(SlhDsaVerifier.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void slhDsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    SlhDsaParameters parameters =
        SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.TINK);
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
    } else {
      assertThat(SlhDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123)).isNotNull();
    }
  }

  @Test
  public void compositeMlDsaSignerAndVerifierCreate() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(
            CompositeMlDsaTestUtil.compositeMlDsaTestVectors.get(2));
    CompositeMlDsaPublicKey publicKey = privateKey.getPublicKey();
    if (TinkFips.useOnlyFips()) {
      assertThrows(GeneralSecurityException.class, () -> CompositeMlDsaSigner.create(privateKey));
      assertThrows(GeneralSecurityException.class, () -> CompositeMlDsaVerifier.create(publicKey));
    } else {
      assertThat(CompositeMlDsaSigner.create(privateKey)).isNotNull();
      assertThat(CompositeMlDsaVerifier.create(publicKey)).isNotNull();
    }
  }

  @Test
  public void compositeMlDsaKeyCreatorCreateKey() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P256)
            .setVariant(CompositeMlDsaParameters.Variant.TINK)
            .build();
    if (TinkFips.useOnlyFips()) {
      assertThrows(
          GeneralSecurityException.class,
          () -> CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123));
    } else {
      assertThat(CompositeMlDsaKeyCreator.createKey(parameters, /* idRequirement= */ 123))
          .isNotNull();
    }
  }
}
