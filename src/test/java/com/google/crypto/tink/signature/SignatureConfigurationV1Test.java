// Copyright 2025 Google LLC
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

import static java.util.Arrays.stream;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization;
import com.google.crypto.tink.signature.internal.MlDsaProtoSerialization;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
import com.google.crypto.tink.signature.internal.SlhDsaProtoSerialization;
import com.google.crypto.tink.signature.internal.SlhDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.signature.internal.testing.SlhDsaTestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class SignatureConfigurationV1Test {
  @BeforeClass
  public static void setUp() throws Exception {
    EcdsaProtoSerialization.register();
    RsaSsaPssProtoSerialization.register();
    RsaSsaPkcs1ProtoSerialization.register();
    Ed25519ProtoSerialization.register();
    MlDsaProtoSerialization.register();
    SlhDsaProtoSerialization.register();
  }

  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, SignatureConfigurationV1::get);
  }

  /**
   * Tests that when using the public API of Tink, signatures in the test vector can be verified.
   * This additionally ensures that all the expected algorithms (Ecdsa, RsaSsaPss, RsaSsaPkcs1,
   * Ed25519 for {@code PublicKeyVerify}, as well as MlDsa and SlhDsa if Conscrypt is available and
   * has support) are present in the SignatureConfigurationV1.
   */
  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("signatureTests") SignatureTestVector testVector) throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    if ((testVector.getPrivateKey() instanceof MlDsaPrivateKey
            && !MlDsaVerifyConscrypt.isSupported())
        || (testVector.getPrivateKey() instanceof SlhDsaPrivateKey
            && !SlhDsaVerifyConscrypt.isSupported())) {
      // ML-DSA/SLH-DSA requires Conscrypt to be available. This also captures cases where
      // ML-DSA/SLH-DSA is not
      // available even with Conscrypt installed, since 1) an older version of Conscrypt may be in
      // use and 2) Conscrypt on Android does not support ML-DSA/SLH-DSA yet.
      return;
    }

    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);

    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  /**
   * Tests that when using the public API of Tink, newly created signatures can be verified. This
   * additionally ensures that all the expected algorithms (Ecdsa, RsaSsaPss, RsaSsaPkcs1, Ed25519
   * for {@code PublicKeySign}, as well as MlDsa and SlhDsa if Conscrypt is available and has
   * support) are present in the SignatureConfigurationV1.
   */
  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("signatureTests") SignatureTestVector testVector) throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }

    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    if ((testVector.getPrivateKey() instanceof MlDsaPrivateKey
            && !MlDsaVerifyConscrypt.isSupported())
        || (testVector.getPrivateKey() instanceof SlhDsaPrivateKey
            && !SlhDsaVerifyConscrypt.isSupported())) {
      // ML-DSA/SLH-DSA requires Conscrypt to be available. This also captures cases where
      // ML-DSA/SLH-DSA is not
      // available even with Conscrypt installed, since 1) an older version of Conscrypt may be in
      // use and 2) Conscrypt on Android does not support ML-DSA/SLH-DSA yet.
      assertThrows(
          GeneralSecurityException.class,
          () -> handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class));
      assertThrows(
          GeneralSecurityException.class,
          () ->
              handle
                  .getPublicKeysetHandle()
                  .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class));
      return;
    }

    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);

    verifier.verify(signature, testVector.getMessage());
  }

  private static byte[] modifyInput(byte[] message) {
    if (message.length == 0) {
      return new byte[] {1};
    }
    byte[] copy = Arrays.copyOf(message, message.length);
    copy[0] ^= 1;
    return copy;
  }

  /**
   * Ensures correctness in the faulty scenario of the Sign/Verify primitives obtained through the
   * public API of Tink.
   */
  @Theory
  public void test_computeFreshSignatureWithTestVector_throwsWithWrongMessage(
      @FromDataPoints("signatureTests") SignatureTestVector testVector) throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    if ((testVector.getPrivateKey() instanceof MlDsaPrivateKey
            && !MlDsaVerifyConscrypt.isSupported())
        || (testVector.getPrivateKey() instanceof SlhDsaPrivateKey
            && !SlhDsaVerifyConscrypt.isSupported())) {
      // ML-DSA/SLH-DSA requires Conscrypt to be available. This also captures cases where
      // ML-DSA/SLH-DSA is not
      // available even with Conscrypt installed, since 1) an older version of Conscrypt may be in
      // use and 2) Conscrypt on Android does not support ML-DSA/SLH-DSA yet.
      return;
    }

    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV1.get(), PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV1.get(), PublicKeyVerify.class);

    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(signature, modifyInput(testVector.getMessage())));
  }

  @DataPoints("signatureTests")
  public static final SignatureTestVector[] signatureTestVectors =
      Stream.concat(
              Stream.concat(
                  Stream.concat(
                      stream(EcdsaTestUtil.createEcdsaTestVectors()),
                      stream(RsaSsaPssTestUtil.createRsaPssTestVectors())),
                  Stream.concat(
                      stream(RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()),
                      stream(Ed25519TestUtil.createEd25519TestVectors()))),
              Stream.concat(
                  MlDsaTestUtil.createMlDsa65ValidSignatureTestVectors(),
                  SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors()))
          .toArray(SignatureTestVector[]::new);
}
