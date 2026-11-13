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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.SignPrehash;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class MlDsaSignPrehashConscryptTest {
  private static final byte[] testData = "this is some data to be signed".getBytes(UTF_8);

  // The test vectors of MlDsaTestUtil use the ID requirement 0x12345678 for variants with an ID
  // requirement.
  private static final MlDsaPrivateKey TINK_ML_DSA_44_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_44, Variant.TINK);
  private static final MlDsaPrivateKey TINK_ML_DSA_65_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_65, Variant.TINK);
  private static final MlDsaPrivateKey TINK_ML_DSA_87_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_87, Variant.TINK);
  private static final MlDsaPrivateKey NO_PREFIX_WITH_PREHASH_ID_ML_DSA_44_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX_WITH_PREHASH_ID);
  private static final MlDsaPrivateKey NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX_WITH_PREHASH_ID);
  private static final MlDsaPrivateKey NO_PREFIX_WITH_PREHASH_ID_ML_DSA_87_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX_WITH_PREHASH_ID);
  private static final MlDsaPrivateKey NO_PREFIX_ML_DSA_65_PRIVATE_KEY =
      createPrivateKey(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX);

  @DataPoints("privateKeysWithIdRequirement")
  public static final MlDsaPrivateKey[] privateKeysWithIdRequirement =
      new MlDsaPrivateKey[] {
        TINK_ML_DSA_44_PRIVATE_KEY,
        TINK_ML_DSA_65_PRIVATE_KEY,
        TINK_ML_DSA_87_PRIVATE_KEY,
        NO_PREFIX_WITH_PREHASH_ID_ML_DSA_44_PRIVATE_KEY,
        NO_PREFIX_WITH_PREHASH_ID_ML_DSA_65_PRIVATE_KEY,
        NO_PREFIX_WITH_PREHASH_ID_ML_DSA_87_PRIVATE_KEY
      };

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }
  }

  private static int signatureLength(MlDsaInstance instance) {
    if (instance == MlDsaInstance.ML_DSA_44) {
      return 2420;
    } else if (instance == MlDsaInstance.ML_DSA_65) {
      return 3309;
    } else {
      return 4627;
    }
  }

  private static MlDsaPrivateKey createPrivateKey(MlDsaInstance instance, Variant variant) {
    return (MlDsaPrivateKey)
        MlDsaTestUtil.getMlDsaValidSignatureTestVector(MlDsaParameters.create(instance, variant))
            .getPrivateKey();
  }

  @Theory
  public void prehashSignVerify_works(
      @FromDataPoints("privateKeysWithIdRequirement") MlDsaPrivateKey privateKey) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    MlDsaPublicKey publicKey = privateKey.getPublicKey();

    Prehash prehash = MlDsaPrehashConscrypt.create(publicKey);
    SignPrehash signer = MlDsaSignPrehashConscrypt.create(privateKey);
    PublicKeyVerify verifier = MlDsaVerifyConscrypt.create(publicKey);

    byte[] outputPrefix = privateKey.getOutputPrefix().toByteArray();
    for (byte[] message : new byte[][] {testData, new byte[0], new byte[1027]}) {
      byte[] signature = signer.sign(prehash.compute(message));

      // The signature starts with the key's output prefix (5 bytes for TINK, empty for
      // NO_PREFIX_WITH_PREHASH_ID) and verifies as a regular ML-DSA signature of the message.
      assertThat(signature)
          .hasLength(
              outputPrefix.length + signatureLength(privateKey.getParameters().getMlDsaInstance()));
      assertThat(Arrays.copyOf(signature, outputPrefix.length)).isEqualTo(outputPrefix);
      verifier.verify(signature, message);
      byte[] otherMessage = Arrays.copyOf(message, message.length + 1);
      assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, otherMessage));
    }
  }

  @Theory
  public void sign_isRandomized(
      @FromDataPoints("privateKeysWithIdRequirement") MlDsaPrivateKey privateKey) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    byte[] prehashValue = MlDsaPrehashConscrypt.create(privateKey.getPublicKey()).compute(testData);
    SignPrehash signer = MlDsaSignPrehashConscrypt.create(privateKey);

    assertThat(signer.sign(prehashValue)).isNotEqualTo(signer.sign(prehashValue));
  }

  @Theory
  public void sign_wrongPrehashLength_throws(
      @FromDataPoints("privateKeysWithIdRequirement") MlDsaPrivateKey privateKey) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    byte[] prehashValue = MlDsaPrehashConscrypt.create(privateKey.getPublicKey()).compute(testData);
    SignPrehash signer = MlDsaSignPrehashConscrypt.create(privateKey);

    byte[] shortPrehash = Arrays.copyOf(prehashValue, prehashValue.length - 1);
    byte[] longPrehash = Arrays.copyOf(prehashValue, prehashValue.length + 1);
    byte[] muOnly = Arrays.copyOfRange(prehashValue, 5, prehashValue.length);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(shortPrehash));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(longPrehash));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(muOnly));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(new byte[0]));
  }

  @Theory
  public void sign_wrongPrehashPrefix_throws(
      @FromDataPoints("privateKeysWithIdRequirement") MlDsaPrivateKey privateKey) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    byte[] prehashValue = MlDsaPrehashConscrypt.create(privateKey.getPublicKey()).compute(testData);
    byte[] mu = Arrays.copyOfRange(prehashValue, 5, prehashValue.length);
    SignPrehash signer = MlDsaSignPrehashConscrypt.create(privateKey);

    // Another key ID, and a prefix which does not start with the prehash start byte.
    byte[] otherKeyId = Bytes.concat(Hex.decode("ff12345679"), mu);
    byte[] wrongStartByte = Bytes.concat(Hex.decode("0112345678"), mu);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(otherKeyId));
    assertThrows(GeneralSecurityException.class, () -> signer.sign(wrongStartByte));
  }

  @Test
  public void sign_prehashOfOtherPublicKey_signatureDoesNotVerify() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    MlDsaPrivateKey privateKey = TINK_ML_DSA_65_PRIVATE_KEY;
    // Has the same ID requirement, and hence the same prehash prefix, as privateKey.
    MlDsaPublicKey otherPublicKey = TINK_ML_DSA_44_PRIVATE_KEY.getPublicKey();
    SignPrehash signer = MlDsaSignPrehashConscrypt.create(privateKey);
    PublicKeyVerify verifier = MlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    // mu is bound to the public key, so the signer cannot tell that the prehash value was computed
    // for another key, but the resulting signature is invalid.
    byte[] signature = signer.sign(MlDsaPrehashConscrypt.create(otherPublicKey).compute(testData));
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void create_keyWithoutIdRequirement_throws() throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }

    assertThrows(
        GeneralSecurityException.class,
        () -> MlDsaSignPrehashConscrypt.create(NO_PREFIX_ML_DSA_65_PRIVATE_KEY));
  }

  @Theory
  public void create_unmatchedKeys_throws(
      @FromDataPoints("privateKeysWithIdRequirement") MlDsaPrivateKey privateKey) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaSignPrehashConscrypt.isSupported()) {
      return;
    }
    byte[] wrongPublicKeyBytes = privateKey.getPublicKey().getSerializedPublicKey().toByteArray();
    wrongPublicKeyBytes[0] ^= 0xFF;
    MlDsaPublicKey wrongPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(privateKey.getParameters())
            .setSerializedPublicKey(com.google.crypto.tink.util.Bytes.copyFrom(wrongPublicKeyBytes))
            .setIdRequirement(privateKey.getPublicKey().getIdRequirementOrNull())
            .build();
    MlDsaPrivateKey wrongPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(wrongPublicKey, privateKey.getPrivateSeed());

    assertThrows(
        GeneralSecurityException.class, () -> MlDsaSignPrehashConscrypt.create(wrongPrivateKey));
  }

  @Test
  public void fips_primitiveCreationFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThat(MlDsaSignPrehashConscrypt.isSupported()).isFalse();
    for (MlDsaPrivateKey privateKey : privateKeysWithIdRequirement) {
      assertThrows(
          GeneralSecurityException.class, () -> MlDsaSignPrehashConscrypt.create(privateKey));
    }
  }

  @Test
  public void noConscryptSupport_primitiveCreationFails() throws Exception {
    Assume.assumeFalse(MlDsaSignPrehashConscrypt.isSupported());

    for (MlDsaPrivateKey privateKey : privateKeysWithIdRequirement) {
      assertThrows(
          GeneralSecurityException.class, () -> MlDsaSignPrehashConscrypt.create(privateKey));
    }
  }
}
