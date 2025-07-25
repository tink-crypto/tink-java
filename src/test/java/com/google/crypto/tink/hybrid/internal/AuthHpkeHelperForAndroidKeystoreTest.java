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
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AuthHpkeHelperForAndroidKeystoreTest {
  @Test
  public void decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector_success()
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
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    byte[] encapsulatedKey =
        Hex.decode(
            "04721adb65bc9d99aeabb5e2b2705979c9c4bc4110a252f784bf7190527625d34021c3338e59c8b86720e3"
                + "fecb2475ba538ebeb1a5b0eef729ec8add7c7fba9634");
    byte[] dhSharedSecret1 =
        Hex.decode("c1ecd8f496f1e9babcfb616460780efac5755de1b59375bd8887cadc2871a173");
    byte[] dhSharedSecret2 =
        Hex.decode("6d72987cf8cab371f22a13fcc2ac9fd53494a600f761fe839946346ee5633149");
    byte[] ciphertextStartingFromByte7 =
        Hex.decode("000000000000009f7c248adec683db2e4140ef3d0c201e146b96439042402a6b3d");
    byte[] contextInfo = Hex.decode("e97f8ccce315e82e2013");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    AuthHpkeHelperForAndroidKeystore helper =
        AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey);
    assertThat(
            Hex.encode(
                helper.decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    encapsulatedKey,
                    dhSharedSecret1,
                    dhSharedSecret2,
                    ciphertextStartingFromByte7,
                    7,
                    contextInfo)))
        .isEqualTo("92b2058b295b7746202d");
  }

  /** Another test vector using AES-256-GCM. */
  @Test
  public void decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector2_success()
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    // We use a manually generated test vector; we cannot use those from RFC 9180 since they
    // all have a non-empty AAD for the Aead.
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04db4aef7b0a93d19450648ea3c9e1f81b8687515782ad178b8914175d72039bd7986e66c96bad1a3b9baf"
                + "cfd435e15795559a9a87f309a18da86b24902c3d8ec1");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "048b9f6c5fce20909c79cb712bf1036cea9cabe3242e1f34828714eff711ef768a304862def203913fd665"
                + "c2a9bd8145bc0b8d5966642582ae5c46ce5ce56f64f7");
    byte[] encapsulatedKey =
        Hex.decode(
            "04c09ad3adfa295fa740bd504172aef9e76bdd7dcce5c38d343e82671955347773c313df518a828078abce"
                + "5a1879733aa5d842db4b629479a9cb6e47c5014e13cc");
    byte[] dhSharedSecret1 =
        Hex.decode("ca74d5462edde9fbde378ca88628244b7205d0242e2f881004e83e0f37a4c68f");
    byte[] dhSharedSecret2 =
        Hex.decode("640b59d3ee95d4935373b4ebefced3a8f713bac41c6687903f9d888edc8190ac");
    byte[] ciphertextStartingFromByte7 =
        Hex.decode("000000000000001cfbdf20428821237f169725cc4496f556150142e9189056cd7c");
    byte[] contextInfo = Hex.decode("3c1a9c66c329db3f4a89");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    AuthHpkeHelperForAndroidKeystore helper =
        AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey);
    assertThat(
            Hex.encode(
                helper.decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    encapsulatedKey,
                    dhSharedSecret1,
                    dhSharedSecret2,
                    ciphertextStartingFromByte7,
                    7,
                    contextInfo)))
        .isEqualTo("f2a13692ea90170104cd");
  }

  @Test
  public void invalidParamsBadVariant_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK) //
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ 1234);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ 1234);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey));
    assertThat(e).hasMessageThat().contains("only supports Variant.NO_PREFIX");
  }

  @Test
  public void invalidParamsBadHKDF_create_throws() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey));
    assertThat(e).hasMessageThat().contains("only supports KdfId.HKDF_SHA256.");
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
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey));
    assertThat(e)
        .hasMessageThat()
        .contains("only supports AeadId.AES_128_GCM and AeadId.AES_256_GCM.");
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
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(params, getP384PublicPointAsBytes(), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(params, getP384PublicPointAsBytes(), /* idRequirement= */ null);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey));
    assertThat(e).hasMessageThat().contains("only supports KemId.DHKEM_P256_HKDF_SHA256");
  }

  @Test
  public void invalidParamsDifferent_create_throws() throws Exception {
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build(),
            Bytes.copyFrom(theirPublicKeyMaterial),
            /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM) // Different AEAD
                .build(),
            Bytes.copyFrom(ourPublicKeyMaterial),
            /* idRequirement= */ null);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey));
    assertThat(e).hasMessageThat().contains("must be equal");
  }

  /**
   * The reversed test of
   * decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector_success.
   */
  @Test
  public void encryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector_success()
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    // The same test vector as above, but we now encrypt, so ourPublicKeyMaterial is now theirs.
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "04f727e47e7bd3ba6e93ac5898f2e0a78e4079d573195bbe2c22eb4b8b679361afe10a0dc3a59e0bd49736"
                + "206f26ffc55b830fb61e49a58b11b16cda3636f72eb6");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04f873fef6483b6c59e3b125cfd824a25068ff3fed93245da71c2c0a843a9de3bcaac4bd8309e67d4d2115"
                + "ac74b6cde00d2f5c4ea4caf709462ddb3e66d7439a89");
    byte[] encapsulatedKey =
        Hex.decode(
            "04721adb65bc9d99aeabb5e2b2705979c9c4bc4110a252f784bf7190527625d34021c3338e59c8b86720e3"
                + "fecb2475ba538ebeb1a5b0eef729ec8add7c7fba9634");
    ECPoint encapsulatedKeyAsObject =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P256, PointFormatType.UNCOMPRESSED, encapsulatedKey);
    byte[] dhSharedSecret1 =
        Hex.decode("c1ecd8f496f1e9babcfb616460780efac5755de1b59375bd8887cadc2871a173");
    byte[] dhSharedSecret2 =
        Hex.decode("6d72987cf8cab371f22a13fcc2ac9fd53494a600f761fe839946346ee5633149");
    byte[] contextInfo = Hex.decode("e97f8ccce315e82e2013");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    AuthHpkeHelperForAndroidKeystore helper =
        AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey);
    assertThat(
            Hex.encode(
                helper.encryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    encapsulatedKeyAsObject,
                    dhSharedSecret1,
                    dhSharedSecret2,
                    Hex.decode("92b2058b295b7746202d"),
                    contextInfo)))
        .isEqualTo(
            "04721adb65bc9d99aeabb5e2b2705979c9c4bc4110a252f784bf7190527625d34021c3338e59c8b86720e3"
                + "fecb2475ba538ebeb1a5b0eef729ec8add7c7fba96349f7c248adec683db2e4140ef3d0c201e146b"
                + "96439042402a6b3d");
  }

  /**
   * The reversed test of
   * decryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector2_success.
   */
  @Test
  public void encryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret_testVector2_success()
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    // The same test vector as above, but we now encrypt, so ourPublicKeyMaterial is now theirs.
    byte[] ourPublicKeyMaterial =
        Hex.decode(
            "048b9f6c5fce20909c79cb712bf1036cea9cabe3242e1f34828714eff711ef768a304862def203913fd665"
                + "c2a9bd8145bc0b8d5966642582ae5c46ce5ce56f64f7");
    byte[] theirPublicKeyMaterial =
        Hex.decode(
            "04db4aef7b0a93d19450648ea3c9e1f81b8687515782ad178b8914175d72039bd7986e66c96bad1a3b9baf"
                + "cfd435e15795559a9a87f309a18da86b24902c3d8ec1");
    byte[] encapsulatedKey =
        Hex.decode(
            "04c09ad3adfa295fa740bd504172aef9e76bdd7dcce5c38d343e82671955347773c313df518a828078abce"
                + "5a1879733aa5d842db4b629479a9cb6e47c5014e13cc");
    ECPoint encapsulatedKeyAsObject =
        EllipticCurves.pointDecode(
            EllipticCurves.CurveType.NIST_P256, PointFormatType.UNCOMPRESSED, encapsulatedKey);
    byte[] dhSharedSecret1 =
        Hex.decode("ca74d5462edde9fbde378ca88628244b7205d0242e2f881004e83e0f37a4c68f");
    byte[] dhSharedSecret2 =
        Hex.decode("640b59d3ee95d4935373b4ebefced3a8f713bac41c6687903f9d888edc8190ac");
    byte[] contextInfo = Hex.decode("3c1a9c66c329db3f4a89");
    HpkePublicKey theirPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(theirPublicKeyMaterial), /* idRequirement= */ null);
    HpkePublicKey ourPublicKey =
        HpkePublicKey.create(
            params, Bytes.copyFrom(ourPublicKeyMaterial), /* idRequirement= */ null);
    AuthHpkeHelperForAndroidKeystore helper =
        AuthHpkeHelperForAndroidKeystore.create(ourPublicKey, theirPublicKey);
    assertThat(
            Hex.encode(
                helper.encryptAuthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    encapsulatedKeyAsObject,
                    dhSharedSecret1,
                    dhSharedSecret2,
                    Hex.decode("f2a13692ea90170104cd"),
                    contextInfo)))
        .isEqualTo(
            "04c09ad3adfa295fa740bd504172aef9e76bdd7dcce5c38d343e82671955347773c313df518a828078abce"
                + "5a1879733aa5d842db4b629479a9cb6e47c5014e13cc1cfbdf20428821237f169725cc4496f55615"
                + "0142e9189056cd7c");
  }
}
