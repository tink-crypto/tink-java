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
// ////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaPrivateKey;
import com.google.crypto.tink.signature.SlhDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.signature.internal.testing.SlhDsaTestUtil;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@AccessesPartialKey
public final class SlhDsaSignConscryptTest {

  private static final int SLH_DSA_SHA2_128S_SIGNATURE_BYTES = 7856;

  private static final byte[] testData = "this is some data to be signed".getBytes(UTF_8);

  // Test vector from tink/go/internal/signature/slhdsa/slhdsa_kat_vectors_test.go
  private static final String PRIVATE_KEY_HEX =
      "5b13979e405179ea3c7b250ddf5637bc081990d028080b35f09b1db79bd9083d66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final String PUBLIC_KEY_HEX =
      "66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";

  private static final SecretBytes PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(Hex.decode(PRIVATE_KEY_HEX), InsecureSecretKeyAccess.get());
  private static final Bytes PUBLIC_KEY_BYTES = Bytes.copyFrom(Hex.decode(PUBLIC_KEY_HEX));

  private static SlhDsaPublicKey noPrefixPublicKey;
  private static SlhDsaPrivateKey noPrefixPrivateKey;
  private static SlhDsaPublicKey tinkPublicKey;
  private static SlhDsaPrivateKey tinkPrivateKey;

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }
    noPrefixPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(
                SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(PUBLIC_KEY_BYTES)
            .build();
    noPrefixPrivateKey =
        SlhDsaPrivateKey.createWithoutVerification(noPrefixPublicKey, PRIVATE_KEY_BYTES);
    tinkPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(
                SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.TINK))
            .setSerializedPublicKey(PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();
    tinkPrivateKey = SlhDsaPrivateKey.createWithoutVerification(tinkPublicKey, PRIVATE_KEY_BYTES);
  }

  @Test
  public void signAndVerify_noPrefix() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = SlhDsaSignConscrypt.create(noPrefixPrivateKey);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(noPrefixPublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(SLH_DSA_SHA2_128S_SIGNATURE_BYTES);
    verifier.verify(signature, testData);
  }

  @Test
  public void signAndVerify_tinkPrefix() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = SlhDsaSignConscrypt.create(tinkPrivateKey);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(tinkPublicKey);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(5 + SLH_DSA_SHA2_128S_SIGNATURE_BYTES);
    assertThat(Hex.encode(Arrays.copyOf(signature, 1))).isEqualTo("01");
    assertThat(Hex.encode(Arrays.copyOfRange(signature, 1, 5))).isEqualTo("12345678");
    verifier.verify(signature, testData);
  }

  @Test
  public void verify_goldenTest_works() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    for (SignatureTestVector testVector :
        SlhDsaTestUtil.createSlhDsaValidSignatureTestVectors()
            .toArray(SignatureTestVector[]::new)) {
      SlhDsaPrivateKey privateKey = (SlhDsaPrivateKey) testVector.getPrivateKey();
      PublicKeySign signer = SlhDsaSignConscrypt.create(privateKey);
      PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(privateKey.getPublicKey());
      byte[] message = testVector.getMessage();

      verifier.verify(signer.sign(message), message);
      verifier.verify(testVector.getSignature(), message);
    }
  }

  @Test
  public void verify_invalidSignature_fails() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = SlhDsaSignConscrypt.create(noPrefixPrivateKey);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(noPrefixPublicKey);

    byte[] signature = signer.sign(testData);
    signature[10] = (byte) (signature[10] ^ 0xFF); // Corrupt signature

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongOutputPrefix_fails() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = SlhDsaSignConscrypt.create(tinkPrivateKey);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(tinkPublicKey);

    byte[] signature = signer.sign(testData);
    signature[1] = (byte) (signature[1] ^ 0xFF); // Corrupt prefix byte

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, testData));
  }

  @Test
  public void verify_wrongSignatureLength_fails() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    PublicKeySign signer = SlhDsaSignConscrypt.create(tinkPrivateKey);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.create(tinkPublicKey);

    byte[] signature = signer.sign(testData);
    byte[] shortSignature = Arrays.copyOf(signature, signature.length - 1);

    assertThrows(GeneralSecurityException.class, () -> verifier.verify(shortSignature, testData));
  }

  @Test
  public void create_unmatchedKeys_fails() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    byte[] wrongPublicKeyBytes =
        Arrays.copyOf(
            PUBLIC_KEY_BYTES.toByteArray(), SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES / 2);
    wrongPublicKeyBytes[0] ^= 0xFF;
    SlhDsaPublicKey wrongPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(
                SlhDsaParameters.createSlhDsaWithSha2And128S(SlhDsaParameters.Variant.NO_PREFIX))
            .setSerializedPublicKey(Bytes.copyFrom(wrongPublicKeyBytes))
            .build();
    SlhDsaPrivateKey wrongPrivateKey =
        SlhDsaPrivateKey.createWithoutVerification(wrongPublicKey, PRIVATE_KEY_BYTES);

    assertThrows(GeneralSecurityException.class, () -> SlhDsaSignConscrypt.create(wrongPrivateKey));
  }

  @Test
  public void fips_isSupported_returnsFalse() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertFalse(SlhDsaSignConscrypt.isSupported());
    assertFalse(SlhDsaVerifyConscrypt.isSupported());
  }

  @Test
  public void fips_primitiveCreationFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, () -> SlhDsaSignConscrypt.create(tinkPrivateKey));
    assertThrows(GeneralSecurityException.class, () -> SlhDsaVerifyConscrypt.create(tinkPublicKey));
  }

  @Test
  public void noConscryptSupport_primitiveCreationFails() throws Exception {
    Assume.assumeFalse(SlhDsaVerifyConscrypt.isSupported());

    assertThrows(GeneralSecurityException.class, () -> SlhDsaSignConscrypt.create(tinkPrivateKey));
    assertThrows(GeneralSecurityException.class, () -> SlhDsaVerifyConscrypt.create(tinkPublicKey));
  }

  @Test
  public void isSupported_conscryptNotAvailable_returnsFalse() throws Exception {
    Assume.assumeTrue(ConscryptUtil.providerOrNull() == null);

    assertFalse(SlhDsaSignConscrypt.isSupported());
    assertFalse(SlhDsaVerifyConscrypt.isSupported());
  }

  @Test
  public void isSupported_onAndroid_returnsTrueSinceApi37() throws Exception {
    Assume.assumeTrue(Util.isAndroid());

    assertThat(ConscryptUtil.providerOrNull()).isNotNull();

    if (Util.getAndroidApiLevel() >= 37) {
      assertThat(SlhDsaSignConscrypt.isSupported()).isTrue();
      assertThat(SlhDsaVerifyConscrypt.isSupported()).isTrue();
    } else {
      assertThat(SlhDsaSignConscrypt.isSupported()).isFalse();
      assertThat(SlhDsaVerifyConscrypt.isSupported()).isFalse();
    }
  }

@Test
  public void createWithProvider_works() throws Exception {
    Assume.assumeTrue(SlhDsaVerifyConscrypt.isSupported());

    Provider provider = ConscryptUtil.providerOrNull();

    assertNotNull(provider);

    PublicKeySign signer = SlhDsaSignConscrypt.createWithProvider(noPrefixPrivateKey, provider);
    PublicKeyVerify verifier = SlhDsaVerifyConscrypt.createWithProvider(noPrefixPublicKey, provider);

    byte[] signature = signer.sign(testData);

    assertThat(signature).hasLength(7856);
    verifier.verify(signature, testData);
  }


  @Test
  public void createWithProvider_providerIsNull_throws() throws Exception {
    Provider nullProvider = null;
    assertThrows(
        NullPointerException.class,
        () -> SlhDsaSignConscrypt.createWithProvider(noPrefixPrivateKey, nullProvider));
    assertThrows(
        NullPointerException.class,
        () -> SlhDsaVerifyConscrypt.createWithProvider(noPrefixPublicKey, nullProvider));
  }
}
