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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil.CompositeMlDsaTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@LowLevelCryptoCaller
@AccessesPartialKey
public final class CompositeMlDsaSignVerifyConscryptTest {

  @DataPoints("testVectors")
  public static final List<CompositeMlDsaTestVector> testVectors =
      CompositeMlDsaTestUtil.compositeMlDsaTestVectors;

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }
  }

  private static CompositeMlDsaPrivateKey createCompositeKeyFromRawBytes(
      String tcId, byte[] pkBytes, byte[] skBytes, Integer idRequirement) throws Exception {
    CompositeMlDsaParameters.MlDsaInstance mlDsaInstance;
    MlDsaParameters.MlDsaInstance innerMlDsaInstance;
    int mlDsaPubSize;
    if (tcId.contains("MLDSA44")) {
      mlDsaInstance = CompositeMlDsaParameters.MlDsaInstance.ML_DSA_44;
      innerMlDsaInstance = MlDsaParameters.MlDsaInstance.ML_DSA_44;
      mlDsaPubSize = 1312;
    } else if (tcId.contains("MLDSA65")) {
      mlDsaInstance = CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65;
      innerMlDsaInstance = MlDsaParameters.MlDsaInstance.ML_DSA_65;
      mlDsaPubSize = 1952;
    } else if (tcId.contains("MLDSA87")) {
      mlDsaInstance = CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87;
      innerMlDsaInstance = MlDsaParameters.MlDsaInstance.ML_DSA_87;
      mlDsaPubSize = 2592;
    } else {
      // Should never happen.
      throw new IllegalArgumentException("Unsupported ML-DSA algorithm: " + tcId);
    }

    byte[] mlDsaPubBytes = Arrays.copyOfRange(pkBytes, 0, mlDsaPubSize);
    byte[] tradPublicKeyBytes = Arrays.copyOfRange(pkBytes, mlDsaPubSize, pkBytes.length);

    byte[] mlDsaSeedBytes = Arrays.copyOfRange(skBytes, 0, 32);
    byte[] tradPrivateKeyBytes = Arrays.copyOfRange(skBytes, 32, skBytes.length);

    MlDsaPublicKey mlDsaPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(
                MlDsaParameters.create(innerMlDsaInstance, MlDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(Bytes.copyFrom(mlDsaPubBytes))
            .build();
    MlDsaPrivateKey mlDsaPrivateKey =
        MlDsaPrivateKey.createWithoutVerification(
            mlDsaPublicKey, SecretBytes.copyFrom(mlDsaSeedBytes, InsecureSecretKeyAccess.get()));

    Ed25519PublicKey edPublicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, Bytes.copyFrom(tradPublicKeyBytes), null);
    Ed25519PrivateKey edPrivateKey =
        Ed25519PrivateKey.create(
            edPublicKey, SecretBytes.copyFrom(tradPrivateKeyBytes, InsecureSecretKeyAccess.get()));

    CompositeMlDsaParameters.Variant variant =
        idRequirement == null
            ? CompositeMlDsaParameters.Variant.NO_PREFIX
            : CompositeMlDsaParameters.Variant.TINK;
    CompositeMlDsaParameters parameters =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(mlDsaInstance)
            .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
            .setVariant(variant)
            .build();

    CompositeMlDsaPrivateKey.Builder builder =
        CompositeMlDsaPrivateKey.builder()
            .setParameters(parameters)
            .setMlDsaPrivateKey(mlDsaPrivateKey)
            .setClassicalPrivateKey(edPrivateKey);
    if (idRequirement != null) {
      builder.setIdRequirement(idRequirement);
    }
    return builder.build();
  }

  @Theory
  public void signAndVerify_success(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = "test message".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }

  @Theory
  public void verifyTestVector_success(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = Hex.decode(testVector.m);

    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    verifier.verify(Hex.decode(testVector.s), message);
  }

  @Theory
  public void verify_modifiedMessage_throws(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = "test message".getBytes(UTF_8);
    byte[] modifiedMessage = "test message!".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, modifiedMessage));
  }

  @Theory
  public void verify_modifiedSignature_throws(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = "test message".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);
    byte[] modifiedSignature = signature.clone();
    modifiedSignature[modifiedSignature.length - 1] ^= 0x01;

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(modifiedSignature, message));
  }

  @Theory
  public void verify_wrongOutputPrefix_throws(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    assumeTrue(testVector.idRequirement != null);
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }

    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = "test message".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);

    // Corrupt header byte: change 0x01 to 0x02.
    byte[] wrongHeaderSignature = signature.clone();
    wrongHeaderSignature[0] = 0x02;
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(wrongHeaderSignature, message));
  }

  @Theory
  public void verify_wrongSignatureLength_throws(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeTrue(testVector.tcId.contains("Ed25519"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }

    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVector.tcId,
            Hex.decode(testVector.pk),
            Hex.decode(testVector.sk),
            testVector.idRequirement);
    byte[] message = "test message".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);
    byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);
    byte[] longSignature = Arrays.copyOf(signature, signature.length + 1);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(shortSignature, message));
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(longSignature, message));
  }

  @Test
  public void throwsIfNotAvailable() throws Exception {
    assumeFalse(CompositeMlDsaVerifyConscrypt.isSupported());
    CompositeMlDsaPrivateKey privateKey =
        createCompositeKeyFromRawBytes(
            testVectors.get(2).tcId,
            Hex.decode(testVectors.get(2).pk),
            Hex.decode(testVectors.get(2).sk),
            testVectors.get(2).idRequirement);

    assertThrows(
        GeneralSecurityException.class, () -> CompositeMlDsaSignConscrypt.create(privateKey));
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey()));
  }
}
