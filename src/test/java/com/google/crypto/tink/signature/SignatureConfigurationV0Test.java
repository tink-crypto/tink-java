// Copyright 2024 Google LLC
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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.internal.Ed25519ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
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
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class SignatureConfigurationV0Test {
  @BeforeClass
  public static void setUp() throws Exception {
    EcdsaProtoSerialization.register();
    RsaSsaPssProtoSerialization.register();
    RsaSsaPkcs1ProtoSerialization.register();
    Ed25519ProtoSerialization.register();
  }

  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, SignatureConfigurationV0::get);
  }

  /**
   * Tests that when using the public API of Tink, signatures in the test vector can be verified.
   * This additionally ensures that all the expected algorithms (Ecdsa, RsaSsaPss, RsaSsaPkcs1,
   * Ed25519 for {@code PublicKeyVerify}) are present in the SignatureConfigurationV0.
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
            .getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class);

    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  /**
   * Tests that when using the public API of Tink, newly created signatures can be verified. This
   * additionally ensures that all the expected algorithms (Ecdsa, RsaSsaPss, RsaSsaPkcs1, Ed25519
   * for {@code PublicKeySign}) are present in the SignatureConfigurationV0.
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

    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class);

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
    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    PublicKeySign signer = handle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class);

    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(signature, modifyInput(testVector.getMessage())));
  }

  @DataPoints("signatureTests")
  public static final SignatureTestVector[] signatureTestVectors =
      Stream.concat(
              Stream.concat(
                  Arrays.stream(EcdsaTestUtil.createEcdsaTestVectors()),
                  Arrays.stream(RsaSsaPssTestUtil.createRsaPssTestVectors())),
              Stream.concat(
                  Arrays.stream(RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()),
                  Arrays.stream(Ed25519TestUtil.createEd25519TestVectors())))
          .toArray(SignatureTestVector[]::new);

  @Test
  public void config_handlesEd25519LegacyKeyForPublicKeySign() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                .setPublicKey(
                    com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                        .setKeyValue(
                            ByteString.copyFrom(
                                Hex.decode(
                                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")))
                        .build())
                .setKeyValue(
                    ByteString.copyFrom(
                        Hex.decode(
                            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Ed25519ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class))
        .isNotNull();
  }

  @Test
  public void config_handlesEd25519LegacyKeyForPublicKeyVerify() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
            com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                .setKeyValue(
                    ByteString.copyFrom(
                        Hex.decode(
                            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Ed25519ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class))
        .isNotNull();
  }

  @Test
  public void config_handlesEcdsaLegacyKeyForPublicKeySign() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            com.google.crypto.tink.proto.EcdsaPrivateKey.newBuilder()
                .setPublicKey(
                    com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                        .setParams(
                            com.google.crypto.tink.proto.EcdsaParams.newBuilder()
                                .setHashType(com.google.crypto.tink.proto.HashType.SHA256)
                                .setCurve(EllipticCurveType.NIST_P256)
                                .setEncoding(
                                    com.google.crypto.tink.proto.EcdsaSignatureEncoding.IEEE_P1363)
                                .build())
                        .setX(
                            ByteString.copyFrom(
                                Hex.decode(
                                    "0060FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")))
                        .setY(
                            ByteString.copyFrom(
                                Hex.decode(
                                    "007903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")))
                        .build())
                .setKeyValue(
                    ByteString.copyFrom(
                        Hex.decode(
                            "00C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")))
                .setVersion(0)
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    EcdsaProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class))
        .isNotNull();
  }

  @Test
  public void config_handlesEcdsaLegacyKeyForPublicKeyVerify() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            com.google.crypto.tink.proto.EcdsaPublicKey.newBuilder()
                .setParams(
                    com.google.crypto.tink.proto.EcdsaParams.newBuilder()
                        .setHashType(com.google.crypto.tink.proto.HashType.SHA256)
                        .setCurve(EllipticCurveType.NIST_P256)
                        .setEncoding(com.google.crypto.tink.proto.EcdsaSignatureEncoding.IEEE_P1363)
                        .build())
                .setX(
                    ByteString.copyFrom(
                        Hex.decode(
                            "0060FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")))
                .setY(
                    ByteString.copyFrom(
                        Hex.decode(
                            "007903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    EcdsaProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class))
        .isNotNull();
  }

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  private static final BigInteger EXPONENT = new BigInteger(1, Base64.urlSafeDecode("AQAB"));
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));
  private static final BigInteger P =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
                  + "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
                  + "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"));
  private static final BigInteger Q =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I"
                  + "edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK"
                  + "rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"));
  private static final BigInteger D =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
                  + "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
                  + "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
                  + "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
                  + "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
                  + "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"));
  private static final BigInteger DP =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3"
                  + "tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w"
                  + "Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c"));
  private static final BigInteger DQ =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
                  + "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
                  + "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots"));
  private static final BigInteger Q_INV =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
                  + "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
                  + "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"));

  // Test vector from Wycheproof's testvectors_v1/rsa_pkcs1_4096_test.json.
  static final BigInteger MODULUS_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkr"
                  + "xcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKK"
                  + "iroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvp"
                  + "tGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-"
                  + "cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7K"
                  + "UiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgs"
                  + "l46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12"
                  + "ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1w"
                  + "y0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd"
                  + "2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju"
                  + "0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7O"
                  + "Nfg9Y2281av0hToFHblNUEU"));
  private static final BigInteger P_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "_CG4VcWtTKK2lwUWQG9xxuee_EEm5lmHctseCC3msN3aqiopUfBBSOhuC94o"
                  + "ITt_YA-YcwgwHqzqE0Biuww932KNqav5PvHOPnWwlTpITb01VL1cBkmTPdd-"
                  + "UnVj6Q8FqAE_3ayVjDKTeOlDA7MEvl-d8f5bBDp_3ZRwCj8LHLvQUWt82UxX"
                  + "ypbZ_SqMqXOZEhjLozocI9gQ91GdH3cCq3Kv_bP4ShsqiBFuQDO8TQz8eYnG"
                  + "V-D-lOlkR2rli65reHbzbAnTKxpj-MR8lKdMku7fdfwnz_4PhFI2PkvI92U_"
                  + "PLVer2k87HDRPIdd6TWosgQ5q36T92mBxZV_xbtE2Q"));
  private static final BigInteger Q_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "-cf3SKUF0j7O-ahfgJfIz31wKO9skOIqM2URWC0sw2NuNOrTcgTb0i8UKj-x"
                  + "1fhXsDEMekM_Ua4U1GCLAbQ6qMeuZ4Nff74LnZeUiznpui06FoftuLVu5w_w"
                  + "U22rTQVR9x7Q2u6eQSRJ9fCZvMFeTvBVTcefh_7FoN6nF8cFQ5K_REYTk3QB"
                  + "u-88Ivv35zjFh3m5gWCaH5wR3W8LvpmW4nc0WeTO8kewKp_CEpasV6WxBWGC"
                  + "QxDPvezJDgZZg3DjaYcT_b4lKOxO89zKrnAe7cPlStbnr05o47Ob0ul6yRGZ"
                  + "NsZHpQNRHLKD35hM_XwH8PVqqK4xZpSO8_QbCFmTTQ"));
  private static final BigInteger D_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BlAoIkQxyjXof4LZcwLJOEtNNBOF7NhRD035TlH6zw2_oBaUE54_AONIWdsJ"
                  + "vQh-dLLhwSKWUuc99-ScL7LdnNp_W0nYGjLpQD5Ll7bu6_226J59j78nuVKC"
                  + "_KlmjmScaCl782e83CGobfwiEyoXfkWRAktd1JrQkXdScfydfLbozYpYWPk_"
                  + "TPKAvwwbadZ15vdgq0Q_qO6N34miqF1GpSw2fCfbbR7GQ15S64bH4KsCsFVD"
                  + "hlQjzE8lNG9V4dtmdeaYMuQ6BMzHivOr1oR37Tdpirf2H6y9vNsyVS3l6J2D"
                  + "QqqfRFuK-sgb_FvAWYHqILNA6Uj3EPez7oXxi1w8WDLyM2cGxenJvY5D0gLn"
                  + "Og9id230txWXXt3TGqZDsUFFBXtJlVVt5hTFezMpe9oOBai4iCopVjvyFobO"
                  + "NMOWD5Bd5zkRmH62luB-rApjhX4olMO0YpR37L8fx26vuyzkoPAPjNtvvWFp"
                  + "45kVFGBSLPWzZdm7uVh9B9rIxDiYKt6p_yQ6hrvfEo6qDTqIhx2M3wgYVCWK"
                  + "ZR_0Im7pdJtKat0JDBWczqBrmhCATl_hUSDMY6WXLqsOQ5gN7a_zIfre6jym"
                  + "DDuhwpgLtZfqeDuAq266h_61dU_R1l18rW-Bz1LBpr_r-ademjFss2TYz0Z9"
                  + "ljcIcd8u5m7hwWlKAiOVg5E"));
  private static final BigInteger DP_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "gVSGqrCgiWv5fxPj6x9_XEkZW0nMO2J3QSo2iHmLGPRkIt9HnLlBs7VOJZZK"
                  + "PWm4l7zINVFg5YtK8p8XRd0sq7Zw9jS5wFjms1FJR_LCfeXtQk9zseHxvkoY"
                  + "iRGgMz86Zohliz7o4yZaUS5N6srcRw7jBOu1IkEjr7RhmE_oUk_gtrMNMqWf"
                  + "btLcdKlrx8v9G7ROWKcJIjXF1icuEqLIYsuMjPXRCapPscZHKHWhRGDB7VIH"
                  + "xLIrxJTHlH63ymOoyv0xNh0ADd8WotefE92RQNl5FJtIjL9ElFpbaq8TIhv0"
                  + "SR67t_yifKIOIh9Jw8N7ifzy3A4stj-Pipt6FCJQWQ"));
  private static final BigInteger DQ_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "th2E_5NKTkN7Fu4bS5_fSuEzcLU4W956VGShI8A0PfV1-eEo7535RCMNOcyc"
                  + "9dwO2yi350C2nvAkwb_uOfzVNA_66gAQFgxTXcCSDnzYG-Uz0A-lVKH8TT4C"
                  + "xGFWn158p4fxUV7fRbGWt1mITeZSw41ZNM-SUk6Ae007WQvDm8QX7kiFp2HS"
                  + "jdrc5sj9s7lh0-f9SAZN-TQKln-LeZl0OIQfSFeaR23bVQiMMI9o8rKdAcZZ"
                  + "elp8jQZihPY-N6aMOHnDKqODZnX9DrJxmIOpGURWHp3X6KprsXFX8IxI-Ob6"
                  + "5cPlortrXVgO7GyX3c2b4KSe8oOnAxrXq6jUON9OlQ"));
  private static final BigInteger Q_INV_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "IvuOX82bdnEE5xJE21MFjBgGHhsNH2O3Pi1ZqV4qEM2HQmoz2hPCh83vgTbl"
                  + "5H6T-5swrZJiintUP0jrARqGNWqzy0gPJ-ORsBjKGH2Xrz2C4xhh7K-mY9t4"
                  + "qonDvUaOaq3vs6Q_eLwAuAFMldtU6dIaAX6PIfZxVF7d6all6jLf_0XNo3_K"
                  + "GqUTL2yO7SIr0B_tWm59Y5WAxZVXd6hlRMLEyTm9uLTEht2lMHKGGgM0NZvb"
                  + "N1hHXknZDQU5lE54z8_Y__Vbsxoc68ZbKPUeeQcBsveRIYiYTwNObpbhxSUe"
                  + "M_44-yIbznqQqGhXxfVrbKdzB8RdUpCx8Iit4IKzSQ"));

  @Test
  public void config_handlesRsaSsaPssLegacyKeyForPublicKeySign() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
            com.google.crypto.tink.proto.RsaSsaPssPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            com.google.crypto.tink.proto.RsaSsaPssParams.newBuilder()
                                .setSigHash(com.google.crypto.tink.proto.HashType.SHA512)
                                .setMgf1Hash(com.google.crypto.tink.proto.HashType.SHA512)
                                .setSaltLength(64)
                                .build())
                        .setN(ByteString.copyFrom(MODULUS_4096.toByteArray()))
                        .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                        .build())
                .setD(ByteString.copyFrom(D_4096.toByteArray()))
                .setP(ByteString.copyFrom(P_4096.toByteArray()))
                .setQ(ByteString.copyFrom(Q_4096.toByteArray()))
                .setDp(ByteString.copyFrom(DP_4096.toByteArray()))
                .setDq(ByteString.copyFrom(DQ_4096.toByteArray()))
                .setCrt(ByteString.copyFrom(Q_INV_4096.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPssProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class))
        .isNotNull();
  }

  @Test
  public void config_handlesRsaSsaPssLegacyKeyForPublicKeyVerify() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
            com.google.crypto.tink.proto.RsaSsaPssPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    com.google.crypto.tink.proto.RsaSsaPssParams.newBuilder()
                        .setSigHash(com.google.crypto.tink.proto.HashType.SHA512)
                        .setMgf1Hash(com.google.crypto.tink.proto.HashType.SHA512)
                        .setSaltLength(64)
                        .build())
                .setN(ByteString.copyFrom(MODULUS_4096.toByteArray()))
                .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPssProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class))
        .isNotNull();
  }

  @Test
  public void config_handlesRsaSsaPkcs1LegacyKeyForPublicKeySign() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            com.google.crypto.tink.proto.RsaSsaPkcs1Params.newBuilder()
                                .setHashType(com.google.crypto.tink.proto.HashType.SHA256))
                        .setN(ByteString.copyFrom(MODULUS.toByteArray()))
                        .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                        .build())
                .setD(ByteString.copyFrom(D.toByteArray()))
                .setP(ByteString.copyFrom(P.toByteArray()))
                .setQ(ByteString.copyFrom(Q.toByteArray()))
                .setDp(ByteString.copyFrom(DP.toByteArray()))
                .setDq(ByteString.copyFrom(DQ.toByteArray()))
                .setCrt(ByteString.copyFrom(Q_INV.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPkcs1ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class))
        .isNotNull();
  }

  @Test
  public void config_handlesRsaSsaPkcs1LegacyKeyForPublicKeyVerify() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    com.google.crypto.tink.proto.RsaSsaPkcs1Params.newBuilder()
                        .setHashType(com.google.crypto.tink.proto.HashType.SHA256))
                .setN(ByteString.copyFrom(MODULUS.toByteArray()))
                .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPkcs1ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class))
        .isNotNull();
  }

  @Test
  public void config_acceptsNon2048Non3072ModulusForRsaSsaPkcs1SignWithLegacyKey()
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
            com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                        .setVersion(0)
                        .setParams(
                            com.google.crypto.tink.proto.RsaSsaPkcs1Params.newBuilder()
                                .setHashType(com.google.crypto.tink.proto.HashType.SHA256))
                        .setN(ByteString.copyFrom(MODULUS_4096.toByteArray()))
                        .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                        .build())
                .setD(ByteString.copyFrom(D_4096.toByteArray()))
                .setP(ByteString.copyFrom(P_4096.toByteArray()))
                .setQ(ByteString.copyFrom(Q_4096.toByteArray()))
                .setDp(ByteString.copyFrom(DP_4096.toByteArray()))
                .setDq(ByteString.copyFrom(DQ_4096.toByteArray()))
                .setCrt(ByteString.copyFrom(Q_INV_4096.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPkcs1ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeySign.class))
        .isNotNull();
  }

  @Test
  public void config_acceptsNon2048Non3072ModulusForRsaSsaPkcs1VerifyWithLegacyKey()
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
            com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    com.google.crypto.tink.proto.RsaSsaPkcs1Params.newBuilder()
                        .setHashType(com.google.crypto.tink.proto.HashType.SHA256))
                .setN(ByteString.copyFrom(MODULUS_4096.toByteArray()))
                .setE(ByteString.copyFrom(EXPONENT.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    RsaSsaPkcs1ProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(SignatureConfigurationV0.get(), PublicKeyVerify.class))
        .isNotNull();
  }
}
