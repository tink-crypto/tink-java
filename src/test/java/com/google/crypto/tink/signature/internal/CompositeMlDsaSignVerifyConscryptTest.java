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
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.CompositeMlDsaTestUtil.CompositeMlDsaTestVector;
import com.google.crypto.tink.subtle.Hex;
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

  @Theory
  public void signAndVerify_success(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeFalse(testVector.tcId.contains("ECDSA"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
    byte[] message = "test message".getBytes(UTF_8);

    PublicKeySign signer = CompositeMlDsaSignConscrypt.create(privateKey);
    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    byte[] signature = signer.sign(message);
    verifier.verify(signature, message);
  }

  @Theory
  public void verifyTestVector_success(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeFalse(testVector.tcId.contains("ECDSA"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
    byte[] message = Hex.decode(testVector.m);

    PublicKeyVerify verifier = CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey());

    verifier.verify(Hex.decode(testVector.s), message);
  }

  @Theory
  public void verify_modifiedMessage_throws(
      @FromDataPoints("testVectors") CompositeMlDsaTestVector testVector) throws Exception {
    assumeFalse(testVector.tcId.contains("ECDSA"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
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
    assumeFalse(testVector.tcId.contains("ECDSA"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }
    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
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
    assumeFalse(testVector.tcId.contains("ECDSA"));
    assumeTrue(testVector.idRequirement != null);
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
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
    assumeFalse(testVector.tcId.contains("ECDSA"));
    if (!CompositeMlDsaVerifyConscrypt.isSupported()) {
      // Cannot test if Composite ML-DSA is not available.
      return;
    }

    CompositeMlDsaPrivateKey privateKey =
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVector);
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
        CompositeMlDsaTestUtil.createCompositeKeyFromTestVector(testVectors.get(2));

    assertThrows(
        GeneralSecurityException.class, () -> CompositeMlDsaSignConscrypt.create(privateKey));
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaVerifyConscrypt.create(privateKey.getPublicKey()));
  }
}
