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
import static java.util.Arrays.stream;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.internal.JsonParser;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.util.Bytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.stream.Stream;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class SignatureJwkSetConverterTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void convertEcdsaJwkSet() throws Exception {
    KeysetHandle publicHandle = createEs256Keyset();

    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSet);

    assertThat(importedHandle.size()).isEqualTo(1);
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey())).isTrue();

    // Verify the exported JWK doesn't have kid
    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    assertThat(jsonKey.has("kid")).isFalse();
    assertThat(jsonKey.get("alg").getAsString()).isEqualTo("ES256");
    assertThat(jsonKey.get("kty").getAsString()).isEqualTo("EC");
    assertThat(jsonKey.get("crv").getAsString()).isEqualTo("P-256");
  }

  @Test
  public void convertEd25519JwkSet() throws Exception {
    KeysetHandle publicHandle = createEd25519Keyset();

    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSet);

    assertThat(importedHandle.size()).isEqualTo(1);
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey())).isTrue();

    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    assertThat(jsonKey.has("kid")).isFalse();
    assertThat(jsonKey.get("alg").getAsString()).isEqualTo("EdDSA");
    assertThat(jsonKey.get("kty").getAsString()).isEqualTo("OKP");
    assertThat(jsonKey.get("crv").getAsString()).isEqualTo("Ed25519");
  }

  @Test
  public void convertRsaSsaPkcs1JwkSet() throws Exception {
    KeysetHandle publicHandle = createRs256Keyset();

    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSet);

    assertThat(importedHandle.size()).isEqualTo(1);
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey())).isTrue();

    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    assertThat(jsonKey.has("kid")).isFalse();
    assertThat(jsonKey.get("alg").getAsString()).isEqualTo("RS256");
    assertThat(jsonKey.get("kty").getAsString()).isEqualTo("RSA");
  }

  @Test
  public void convertRsaSsaPssJwkSet() throws Exception {
    KeysetHandle publicHandle = createPs256Keyset();

    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSet);

    assertThat(importedHandle.size()).isEqualTo(1);
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey())).isTrue();

    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    assertThat(jsonKey.has("kid")).isFalse();
    assertThat(jsonKey.get("alg").getAsString()).isEqualTo("PS256");
    assertThat(jsonKey.get("kty").getAsString()).isEqualTo("RSA");
  }

  @Test
  public void testExportTinkVariantThrows() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    assertThrows(
        GeneralSecurityException.class, () -> SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle));
  }

  @Test
  public void testExportEcdsaDerEncodingThrows() throws Exception {
    // PredefinedSignatureParameters.ECDSA_P256 is TINK variant, but even if we make it RAW,
    // it has DER encoding which should be rejected.
    EcdsaParameters derParams =
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle privateHandle = KeysetHandle.generateNew(derParams);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    assertThrows(
        GeneralSecurityException.class, () -> SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle));
  }

  @Test
  public void testImportWithKidIgnoresKidAndImportsAsRaw() throws Exception {
    // Create a valid JWK but add a custom kid to it.
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(
            PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);

    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    jsonKey.addProperty("kid", "some-custom-kid-string");

    String jwkSetWithKid = jsonKeyset.toString();

    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSetWithKid);

    assertThat(importedHandle.size()).isEqualTo(1);
    // It should be equal to the original public key (which is RAW / NO_PREFIX)
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey())).isTrue();

    // Verify it was imported as NO_PREFIX
    EcdsaPublicKey importedKey = (EcdsaPublicKey) importedHandle.getAt(0).getKey();
    assertThat(importedKey.getParameters().getVariant())
        .isEqualTo(EcdsaParameters.Variant.NO_PREFIX);
  }

  @Test
  public void testImportInvalidJwkThrows() throws Exception {
    String invalidJwkSet =
        "{\"keys\": [{\"kty\": \"EC\", \"alg\": \"ES256\"}]}"; // Missing x, y, crv
    assertThrows(
        GeneralSecurityException.class, () -> SignatureJwkSetConverter.toPublicKeysetHandle(invalidJwkSet));
  }

  @Test
  public void testImportMismatchedHashCurveThrows() throws Exception {
    // alg is ES256 (implies SHA256), but crv is P-384
    String mismatchedJwkSet =
        "{\"keys\": [{\"kty\": \"EC\", \"alg\": \"ES256\", \"crv\": \"P-384\", \"x\": \"fake\", \"y\": \"fake\"}]}";
    assertThrows(
        GeneralSecurityException.class,
        () -> SignatureJwkSetConverter.toPublicKeysetHandle(mismatchedJwkSet));
  }

  private static boolean isSupportedKeyType(SignatureTestVector testVector) {
    SignaturePublicKey publicKey = testVector.getPrivateKey().getPublicKey();
    return (publicKey instanceof EcdsaPublicKey)
        || (publicKey instanceof Ed25519PublicKey)
        || (publicKey instanceof RsaSsaPkcs1PublicKey)
        || (publicKey instanceof RsaSsaPssPublicKey);
  }

  private static KeysetHandle keysetHandleFromPrivateKey(SignaturePrivateKey privateKey)
      throws GeneralSecurityException {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(privateKey).makePrimary();
    Integer id = privateKey.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    return KeysetHandle.newBuilder().addEntry(entry).build();
  }

  private static boolean isCompatible(SignatureTestVector testVector) {
    if (!isSupportedKeyType(testVector)) {
      return false;
    }
    SignaturePublicKey publicKey = testVector.getPrivateKey().getPublicKey();

    if (publicKey instanceof EcdsaPublicKey) {
      EcdsaPublicKey key = (EcdsaPublicKey) publicKey;
      if (key.getParameters().getVariant() != EcdsaParameters.Variant.NO_PREFIX
          || key.getParameters().getSignatureEncoding()
              != EcdsaParameters.SignatureEncoding.IEEE_P1363) {
        return false;
      }
      // Enforce standard curve/hash combinations for JWS compatibility
      EcdsaParameters.CurveType curve = key.getParameters().getCurveType();
      EcdsaParameters.HashType hash = key.getParameters().getHashType();
      if (curve.equals(EcdsaParameters.CurveType.NIST_P256)) {
        return hash.equals(EcdsaParameters.HashType.SHA256);
      }
      if (curve.equals(EcdsaParameters.CurveType.NIST_P384)) {
        return hash.equals(EcdsaParameters.HashType.SHA384);
      }
      if (curve.equals(EcdsaParameters.CurveType.NIST_P521)) {
        return hash.equals(EcdsaParameters.HashType.SHA512);
      }
      return false;
    }
    if (publicKey instanceof Ed25519PublicKey) {
      Ed25519PublicKey key = (Ed25519PublicKey) publicKey;
      return key.getParameters().getVariant() == Ed25519Parameters.Variant.NO_PREFIX;
    }
    if (publicKey instanceof RsaSsaPkcs1PublicKey) {
      RsaSsaPkcs1PublicKey key = (RsaSsaPkcs1PublicKey) publicKey;
      return key.getParameters().getVariant() == RsaSsaPkcs1Parameters.Variant.NO_PREFIX;
    }
    if (publicKey instanceof RsaSsaPssPublicKey) {
      RsaSsaPssPublicKey key = (RsaSsaPssPublicKey) publicKey;
      if (key.getParameters().getVariant() != RsaSsaPssParameters.Variant.NO_PREFIX) {
        return false;
      }
      // Check standard salt length
      int expectedSaltLength;
      RsaSsaPssParameters.HashType hash = key.getParameters().getSigHashType();
      if (hash.equals(RsaSsaPssParameters.HashType.SHA256)) {
        expectedSaltLength = 32;
      } else if (hash.equals(RsaSsaPssParameters.HashType.SHA384)) {
        expectedSaltLength = 48;
      } else if (hash.equals(RsaSsaPssParameters.HashType.SHA512)) {
        expectedSaltLength = 64;
      } else {
        return false;
      }
      return key.getParameters().getSaltLengthBytes() == expectedSaltLength;
    }
    return false;
  }

  @Theory
  public void convertThenVerifyWithCompatibleTestVector(
      @FromDataPoints("signatureTests") SignatureTestVector testVector) throws Exception {
    Assume.assumeTrue(isCompatible(testVector));

    SignaturePrivateKey privateKey = testVector.getPrivateKey();
    KeysetHandle privateHandle = keysetHandleFromPrivateKey(privateKey);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = SignatureJwkSetConverter.toPublicKeysetHandle(jwkSet);

    assertThat(importedHandle.size()).isEqualTo(1);
    assertThat(importedHandle.getAt(0).getKey().equalsKey(publicHandle.getAt(0).getKey()))
        .isTrue();

    // Also verify the signature in the test vector using the imported key
    PublicKeyVerify verifier =
        importedHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  @Theory
  public void convertWithIncompatibleTestVectorThrows(
      @FromDataPoints("signatureTests") SignatureTestVector testVector) throws Exception {
    Assume.assumeFalse(isCompatible(testVector));

    SignaturePrivateKey privateKey = testVector.getPrivateKey();
    KeysetHandle privateHandle = keysetHandleFromPrivateKey(privateKey);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    assertThrows(
        GeneralSecurityException.class,
        () -> SignatureJwkSetConverter.fromPublicKeysetHandle(publicHandle));
  }

  @DataPoints("signatureTests")
  public static final SignatureTestVector[] signatureTestVectors =
      Stream.concat(
              Stream.concat(
                  Stream.concat(
                      stream(EcdsaTestUtil.createEcdsaTestVectors()),
                      stream(RsaSsaPssTestUtil.createRsaPssTestVectors())),
                  stream(RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors())),
              stream(Ed25519TestUtil.createEd25519TestVectors()))
          .toArray(SignatureTestVector[]::new);

  private static final String ES256_JWK_SET =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]}]}";

  private static final String ED25519_JWK_SET =
      "{\"keys\":[{"
          + "\"kty\":\"OKP\","
          + "\"crv\":\"Ed25519\","
          + "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","
          + "\"use\":\"sig\",\"alg\":\"EdDSA\",\"key_ops\":[\"verify\"]}]}";

  private static final String ES384_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-384\","
          + "\"x\":\"0o71ooaChpq-J5Q7iPypL7j7xGa_geG1NDLl0EF4MjTBgKRZtok3qLb-ywkrBt5k\","
          + "\"y\":\"QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO\","
          + "\"use\":\"sig\",\"alg\":\"ES384\",\"key_ops\":[\"verify\"]}]}";

  private static final String ES512_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-521\","
          + "\"x\":\"ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_RYkcxnIWvzpFSK2JFCbV\","
          + "\"y\":\"ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58bqEnaZ0G7W9qjHa2ols2\","
          + "\"use\":\"sig\",\"alg\":\"ES512\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2"
          + "GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN"
          + "6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR"
          + "1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDG"
          + "W-zXzw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"nlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj_mvHXAbacrngt9fzi0iv_W"
          + "Q57jUmtO1b_wLt5LYk9APsBYjywDCIe-u9UouikP7c3SBqjjQijZ50jgYbMY6cL7s2Gx5lI1vlGX3ZExLVYbNo"
          + "I9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH_KzVacTq2_pVXKVH_9_EQzcLB0oYUljZ4vYQ4HCAcwnUZb"
          + "irsRwA0350Dz0Mlj-3-9sSAF8FPA-F_wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7-bxH9p28huJSU96P4WdG5P"
          + "YVwI1VEYwGipkUIpMWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL9h-aBoxruY-m"
          + "U49kAHzzeAntn8C-vIrxN-X6N2EU9N8t9BF-mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXBRrbJyxkIVuqv"
          + "ACP5\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS384\",\"key_ops\":[\"verify\"]}]}";

  private static final String RS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"kKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbgEoQ3XWOgtNvi7QeKLE4GjQ"
          + "a5bY0xdRnu8nKjFcsvH-eu1sV8oVoZ984J5mT1mhwU6nt26p4xKyeapMhzYYNvKudQjQJ8SbpVOFpEiJ7j0ECM"
          + "Ud4Q8mCUqWsrXYE8-1CcHjprsIxdot-haCARc72RBj9cLuBIhJNzlFXNmsYh8yoSiEYr_auRvg_kIlNlnlOK_r"
          + "JM_jMXbB6FuWdePrtqZ-ce2TVyARqjZJ0G0vZcPuvOhgS4LM7_Aeal84ZhIcHladSo_g8pK1eUhnRqRXJpsltw"
          + "ux-1XVJeg2a0FQ0BN3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI-vumSy9dmY4UrgAG37N8Xj5_NeqBT51L3qE6tk2"
          + "ZLoO7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4QyQufK8k8UPiB"
          + "bWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgCK4KzPG7PwV120r6IVGfl"
          + "fpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyXZWCyWKcvTFsGrr1oECwDOmW-nUIHGklr"
          + "9Q0\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS512\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7"
          + "-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZ"
          + "WBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWD"
          + "S_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBX"
          + "LMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2S"
          + "jSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrE"
          + "I2ad\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS256\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"v6a0OergWYmY1k6l6vx6Of5-RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25ehZ5LNDIiGjhE3v2--D7QE"
          + "jnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4kXypVhytjwRdiP61vG0C_eL0x-LijtM_XV"
          + "ee1Y-5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6JzLbWfDRWoqbCXKYivnw-CSE38ddW1XsrAT76E2Vf-womuwy"
          + "BbkjLaiWvNxNFBTap2IaBLKAni6x7pqYCeu1n9eMUi41oz9QM8xfOvpH-wubc2PjwyTsb1FDTLnhV36tQLTVGd"
          + "QdCDMF2Z8Agrnio3n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp_lQrsuWqe4CVJjFE1H4BxcU7L0j8"
          + "755kGJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0-niEwX_L8jqW4YMbxrGdAfk"
          + "TnP\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS384\",\"key_ops\":[\"verify\"]}]}";

  private static final String PS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"nOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0StSIB7EQP4ciHa-vr59sOgM"
          + "FMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4jbScDrwNn1sQ8rkgSNczvQNpV1MtBhS_CC"
          + "1PxVF88JaejG2zr-unoFlw7xnqxBWMzNrMHZHwqga2vL3inSbvA_RGQjnE2DzQSwZkXthGSwYBjOYbGawMN4on"
          + "kAx_myHMyTg_TLAqG9GUyB0DVelvVoGZG_QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG8v1t7PveN-ST"
          + "IdTE2D548K-GDOvsvrO4ZhofS_iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUgN_iwjupk6u1S"
          + "vt-RWNJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb-ooZ6K5-hx3Rld7wXktjYIZzHqUr39P5yTw28"
          + "b8Y2dPFWR4vwr2_0zBxcDmTRRtQ7vPOtZPD0_LVIXkgbBiLILpycnucWt9Lq9Hc62KFiTQOAuuOxz7ObBegXjn"
          + "FupiZZ9PyzO5WgT9lRpH7U7tzGLAjV-AUpjH6HA1o6bRLKOHFBPS-I9IqAYb_RpF6M_6hCmC2Rz64yYzR3y4vH"
          + "KGM\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS512\",\"key_ops\":[\"verify\"]}]}";

  private static final String JWK_SET_WITH_TWO_KEYS =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]},"
          + "{\"kty\":\"RSA\","
          + "\"n\":\"kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2"
          + "GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN"
          + "6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR"
          + "1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDG"
          + "W-zXzw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";

  private static void assertEqualJwkSets(String jwkSet1, String jwkSet2) throws Exception {
    JsonObject parsedjwkSet1 = JsonParser.parse(jwkSet1).getAsJsonObject();
    JsonObject parsedjwkSet2 = JsonParser.parse(jwkSet2).getAsJsonObject();
    JsonArray keys1 = parsedjwkSet1.remove("keys").getAsJsonArray();
    JsonArray keys2 = parsedjwkSet2.remove("keys").getAsJsonArray();
    assertThat(keys1).containsExactlyElementsIn(keys2);
    assertThat(parsedjwkSet1).isEqualTo(parsedjwkSet2);
  }

  private static class KeysetAndJwkSet {
    final KeysetHandle keysetHandle;
    final String jwkSet;

    KeysetAndJwkSet(KeysetHandle keysetHandle, String jwkSet) {
      this.keysetHandle = keysetHandle;
      this.jwkSet = jwkSet;
    }
  }

  @DataPoints("signatureTestCases")
  public static KeysetAndJwkSet[] signatureTestCases() throws Exception {
    return new KeysetAndJwkSet[] {
      new KeysetAndJwkSet(createEs256Keyset(), ES256_JWK_SET),
      new KeysetAndJwkSet(createEs384Keyset(), ES384_JWK_SET),
      new KeysetAndJwkSet(createEs512Keyset(), ES512_JWK_SET),
      new KeysetAndJwkSet(createEd25519Keyset(), ED25519_JWK_SET),
      new KeysetAndJwkSet(createRs256Keyset(), RS256_JWK_SET),
      new KeysetAndJwkSet(createRs384Keyset(), RS384_JWK_SET),
      new KeysetAndJwkSet(createRs512Keyset(), RS512_JWK_SET),
      new KeysetAndJwkSet(createPs256Keyset(), PS256_JWK_SET),
      new KeysetAndJwkSet(createPs384Keyset(), PS384_JWK_SET),
      new KeysetAndJwkSet(createPs512Keyset(), PS512_JWK_SET),
      new KeysetAndJwkSet(createKeysetWithTwoKeys(), JWK_SET_WITH_TWO_KEYS),
    };
  }

  @Theory
  @AccessesPartialKey
  public void convertKeyset_success(
      @FromDataPoints("signatureTestCases") KeysetAndJwkSet testCase) throws Exception {
    String jwkSet = SignatureJwkSetConverter.fromPublicKeysetHandle(testCase.keysetHandle);
    assertEqualJwkSets(jwkSet, testCase.jwkSet);
  }

  @Theory
  public void toPublicKeysetHandle_fromPublicKeysetHandle_success(
      @FromDataPoints("signatureTestCases") KeysetAndJwkSet testCase) throws Exception {
    assertEqualJwkSets(
        SignatureJwkSetConverter.fromPublicKeysetHandle(
            SignatureJwkSetConverter.toPublicKeysetHandle(testCase.jwkSet)),
        testCase.jwkSet);
  }

  @Theory
  public void toPublicKeysetHandle_isImportedAsExpected(
      @FromDataPoints("signatureTestCases") KeysetAndJwkSet testCase) throws Exception {
    KeysetHandle converted = SignatureJwkSetConverter.toPublicKeysetHandle(testCase.jwkSet);
    assertThat(converted.size()).isEqualTo(testCase.keysetHandle.size());
    for (int i = 0; i < converted.size(); i++) {
      assertThat(converted.getAt(i).getKey().equalsKey(testCase.keysetHandle.getAt(i).getKey()))
          .isTrue();
    }
  }

  private static KeysetHandle createEs256Keyset() throws Exception {
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1, Base64.urlSafeDecode("EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA")),
                    new BigInteger(
                        1, Base64.urlSafeDecode("UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(282600252).makePrimary())
        .build();
  }

  private static KeysetHandle createEs384Keyset() throws Exception {
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setHashType(EcdsaParameters.HashType.SHA384)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "0o71ooaChpq-J5Q7iPypL7j7xGa_geG1NDLl0EF4MjTBgKRZtok3qLb-ywkrBt5k")),
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(456087424).makePrimary())
        .build();
  }

  private static KeysetHandle createEs512Keyset() throws Exception {
    EcdsaPublicKey key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setHashType(EcdsaParameters.HashType.SHA512)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P521)
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_RYkcxnIWvzpFSK2JFCbV")),
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58bqEnaZ0G7W9qjHa2ols2"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1570200439).makePrimary())
        .build();
  }

  private static KeysetHandle createRs256Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW-zXzw"));
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(482168993).makePrimary())
        .build();
  }

  private static KeysetHandle createRs384Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "nlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj_mvHXAbacrngt9fzi0iv_WQ57jUmtO1b_wLt5LYk9APsBYjywDCIe-u9UouikP7c3SBqjjQijZ50jgYbMY6cL7s2Gx5lI1vlGX3ZExLVYbNoI9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH_KzVacTq2_pVXKVH_9_EQzcLB0oYUljZ4vYQ4HCAcwnUZbirsRwA0350Dz0Mlj-3-9sSAF8FPA-F_wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7-bxH9p28huJSU96P4WdG5PYVwI1VEYwGipkUIpMWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL9h-aBoxruY-mU49kAHzzeAntn8C-vIrxN-X6N2EU9N8t9BF-mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXBRrbJyxkIVuqvACP5"));
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA384)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(333504275).makePrimary())
        .build();
  }

  private static KeysetHandle createRs512Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbgEoQ3XWOgtNvi7QeKLE4GjQa5bY0xdRnu8nKjFcsvH-eu1sV8oVoZ984J5mT1mhwU6nt26p4xKyeapMhzYYNvKudQjQJ8SbpVOFpEiJ7j0ECMUd4Q8mCUqWsrXYE8-1CcHjprsIxdot-haCARc72RBj9cLuBIhJNzlFXNmsYh8yoSiEYr_auRvg_kIlNlnlOK_rJM_jMXbB6FuWdePrtqZ-ce2TVyARqjZJ0G0vZcPuvOhgS4LM7_Aeal84ZhIcHladSo_g8pK1eUhnRqRXJpsltwux-1XVJeg2a0FQ0BN3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI-vumSy9dmY4UrgAG37N8Xj5_NeqBT51L3qE6tk2ZLoO7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4QyQufK8k8UPiBbWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgCK4KzPG7PwV120r6IVGflfpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyXZWCyWKcvTFsGrr1oECwDOmW-nUIHGklr9Q0"));
    RsaSsaPkcs1PublicKey key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(705596479).makePrimary())
        .build();
  }

  private static KeysetHandle createPs256Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZWBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWDS_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBXLMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2SjSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrEI2ad"));
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                    .setSaltLengthBytes(32)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1508587714).makePrimary())
        .build();
  }

  private static KeysetHandle createPs384Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "v6a0OergWYmY1k6l6vx6Of5-RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25ehZ5LNDIiGjhE3v2--D7QEjnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4kXypVhytjwRdiP61vG0C_eL0x-LijtM_XVee1Y-5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6JzLbWfDRWoqbCXKYivnw-CSE38ddW1XsrAT76E2Vf-womuwyBbkjLaiWvNxNFBTap2IaBLKAni6x7pqYCeu1n9eMUi41oz9QM8xfOvpH-wubc2PjwyTsb1FDTLnhV36tQLTVGdQdCDMF2Z8Agrnio3n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp_lQrsuWqe4CVJjFE1H4BxcU7L0j8755kGJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0-niEwX_L8jqW4YMbxrGdAfkTnP"));
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA384)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA384)
                    .setSaltLengthBytes(48)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1042230435).makePrimary())
        .build();
  }

  private static KeysetHandle createPs512Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "nOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0StSIB7EQP4ciHa-vr59sOgMFMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4jbScDrwNn1sQ8rkgSNczvQNpV1MtBhS_CC1PxVF88JaejG2zr-unoFlw7xnqxBWMzNrMHZHwqga2vL3inSbvA_RGQjnE2DzQSwZkXthGSwYBjOYbGawMN4onkAx_myHMyTg_TLAqG9GUyB0DVelvVoGZG_QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG8v1t7PveN-STIdTE2D548K-GDOvsvrO4ZhofS_iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUgN_iwjupk6u1Svt-RWNJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb-ooZ6K5-hx3Rld7wXktjYIZzHqUr39P5yTw28b8Y2dPFWR4vwr2_0zBxcDmTRRtQ7vPOtZPD0_LVIXkgbBiLILpycnucWt9Lq9Hc62KFiTQOAuuOxz7ObBegXjnFupiZZ9PyzO5WgT9lRpH7U7tzGLAjV-AUpjH6HA1o6bRLKOHFBPS-I9IqAYb_RpF6M_6hCmC2Rz64yYzR3y4vHKGM"));
    RsaSsaPssPublicKey key =
        RsaSsaPssPublicKey.builder()
            .setParameters(
                RsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                    .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                    .setSaltLengthBytes(64)
                    .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(257081135).makePrimary())
        .build();
  }

  private static KeysetHandle createKeysetWithTwoKeys() throws Exception {
    EcdsaPublicKey es256Key =
        EcdsaPublicKey.builder()
            .setParameters(
                EcdsaParameters.builder()
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1, Base64.urlSafeDecode("EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA")),
                    new BigInteger(
                        1, Base64.urlSafeDecode("UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE"))))
            .build();
    BigInteger rs256Modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW-zXzw"));
    RsaSsaPkcs1PublicKey rs256Key =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(
                RsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(rs256Modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                    .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                    .build())
            .setModulus(rs256Modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(es256Key).withFixedId(282600252).makePrimary())
        .addEntry(KeysetHandle.importKey(rs256Key).withFixedId(482168993))
        .build();
  }

  @AccessesPartialKey
  private static KeysetHandle createEd25519Keyset() throws Exception {
    Ed25519PublicKey key =
        Ed25519PublicKey.create(
            Bytes.copyFrom(
                Base64.urlSafeDecode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")));
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
        .build();
  }
}
