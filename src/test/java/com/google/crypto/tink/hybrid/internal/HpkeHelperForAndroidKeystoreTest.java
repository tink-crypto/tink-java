// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HpkeHelperForAndroidKeystoreTest {

  @Test
  public void decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret_success()
      throws Exception {
    HybridTestVector vector = HpkeTestUtil.createTestVector0();
    HpkePrivateKey privateKey = (HpkePrivateKey) vector.getPrivateKey();
    // The shared secret is needed for decryption with
    // decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret  -- we logged it to enable this
    // code.
    byte[] dhSharedSecret =
        Hex.decode("c47e13b026cac2b065b83c5985cc03f683382ed027448b3432fa51d34e54f7e6");

    // Variant NO_PREFIX, DHKEM_P256_HKDF_SHA256 -> the first 65 bytes are the encapsulated key.
    byte[] encapsulatedKey = Arrays.copyOf(vector.getCiphertext(), 65);
    HpkeHelperForAndroidKeystore helper =
        HpkeHelperForAndroidKeystore.create(privateKey.getPublicKey());
    assertThat(
            helper.decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                encapsulatedKey,
                dhSharedSecret,
                vector.getCiphertext(),
                65,
                vector.getContextInfo()))
        .isEqualTo(vector.getPlaintext());
  }

  /** A second test with a test vector. Here only due to history (and it doesn't seem to hurt). */
  @Test
  public void decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector2_success()
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    // We use a manually generated test vector; we cannot use those from RFC 9180 since they
    // all have a non-empty AAD for the Aead.
    byte[] receiverPublicKey =
        Hex.decode(
            "04e01a1eb94f07a2e6b7e198df9fa46455e0f6ceaf8e5aa27d2a3acbfdd5c1cb75a20a371362dbd93d2035"
                + "91db18537e203f3955653abfc9be5c6f5cde1ef747a0");
    byte[] encapsulatedKey =
        Hex.decode(
            "04ccfab30059af0d87d3e593872f0c669ea8d368aa3de2208c9edac080ce8b25bf74e08b4759e7b7e894a9"
                + "aec0d646802cab3c13b9a77e79132924872d59151f0c");
    byte[] dhSharedSecret =
        Hex.decode("2d8c916dec40991559e23a193aeb908db7a50b1cc5394aedb3e95ad37a6a35fd");
    byte[] ciphertextStartingFromByte7 =
        Hex.decode(
            "0000000000000080431f249f0b0cc4a6d9b4742ee52490501a9e25558560be39d51b445b0c6a9420d7a513"
                + "7a968c3b5fe8fa7d7637");
    byte[] contextInfo = Hex.decode("6b638e24759f6b5aa9e8569ffb9e25f1fe34afe7ebbef2f63dda7b42aac0");
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, Bytes.copyFrom(receiverPublicKey), /* idRequirement= */ null);
    HpkeHelperForAndroidKeystore helper = HpkeHelperForAndroidKeystore.create(publicKey);
    assertThat(
            Hex.encode(
                helper.decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    encapsulatedKey, dhSharedSecret, ciphertextStartingFromByte7, 7, contextInfo)))
        .isEqualTo("046d8bbadebab832ec27e7a32f5c37b35b8eb9a452234095d98f8f94e2e5");
  }

  /** Another test with a different Aead configuration. */
  @Test
  public void decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret_success_aes256()
      throws Exception {
    HybridTestVector vector = HpkeTestUtil.createTestVector6();
    HpkePrivateKey privateKey = (HpkePrivateKey) vector.getPrivateKey();
    // The shared secret is needed for decryption with
    // decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret  -- we logged it to enable this
    // code.
    byte[] dhSharedSecret =
        Hex.decode("f44ecab240f71f445d29277289d4952871b503972d5105db61deba5c1f3aaae2");

    // Variant NO_PREFIX, DHKEM_P256_HKDF_SHA256 -> the first 65 bytes are the encapsulated key.
    byte[] encapsulatedKey = Arrays.copyOf(vector.getCiphertext(), 65);
    HpkeHelperForAndroidKeystore helper =
        HpkeHelperForAndroidKeystore.create(privateKey.getPublicKey());
    assertThat(
            helper.decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                encapsulatedKey,
                dhSharedSecret,
                vector.getCiphertext(),
                65,
                vector.getContextInfo()))
        .isEqualTo(vector.getPlaintext());
  }

  @Test
  public void invalidParamsBadVariant_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] receiverPublicKey =
        Hex.decode(
            "04e01a1eb94f07a2e6b7e198df9fa46455e0f6ceaf8e5aa27d2a3acbfdd5c1cb75a20a371362dbd93d2035"
                + "91db18537e203f3955653abfc9be5c6f5cde1ef747a0");
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, Bytes.copyFrom(receiverPublicKey), /* idRequirement= */ 123);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> HpkeHelperForAndroidKeystore.create(publicKey));
    assertThat(thrown).hasMessageThat().contains("only supports Variant.NO_PREFIX");
  }

  private static Bytes getP384PublicPointAsBytes() throws GeneralSecurityException {
    return Bytes.copyFrom(
        EllipticCurves.pointEncode(
            CurveType.NIST_P384,
            PointFormatType.UNCOMPRESSED,
            new ECPoint(
                new BigInteger(
                    "009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c"
                        + "732aa49bc4a38f467edb8424",
                    16),
                new BigInteger(
                    "0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a"
                        + "0b2c990ae92b62d6c75180ba",
                    16))));
  }

  @Test
  public void invalidParamsBadCurve_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] receiverPublicKey = getP384PublicPointAsBytes().toByteArray();
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, Bytes.copyFrom(receiverPublicKey), /* idRequirement= */ null);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> HpkeHelperForAndroidKeystore.create(publicKey));
    assertThat(thrown).hasMessageThat().contains("only supports DHKEM_P256_HKDF_SHA256");
  }

  @Test
  public void invalidParamsBadHkdf_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] receiverPublicKey =
        Hex.decode(
            "04e01a1eb94f07a2e6b7e198df9fa46455e0f6ceaf8e5aa27d2a3acbfdd5c1cb75a20a371362dbd93d2035"
                + "91db18537e203f3955653abfc9be5c6f5cde1ef747a0");
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, Bytes.copyFrom(receiverPublicKey), /* idRequirement= */ null);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> HpkeHelperForAndroidKeystore.create(publicKey));
    assertThat(thrown).hasMessageThat().contains("only supports HKDF_SHA256");
  }

  @Test
  public void invalidParamsBadAead_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
            .build();
    byte[] receiverPublicKey =
        Hex.decode(
            "04e01a1eb94f07a2e6b7e198df9fa46455e0f6ceaf8e5aa27d2a3acbfdd5c1cb75a20a371362dbd93d2035"
                + "91db18537e203f3955653abfc9be5c6f5cde1ef747a0");
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, Bytes.copyFrom(receiverPublicKey), /* idRequirement= */ null);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> HpkeHelperForAndroidKeystore.create(publicKey));
    assertThat(thrown).hasMessageThat().contains("only supports AES_128_GCM");
  }
}
