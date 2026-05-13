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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.internal.JsonParser;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
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
public final class JwkSetConverterTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void convertEcdsaJwkSet() throws Exception {
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(
            PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSet);

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
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519WithRawOutput);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSet);

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
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(
            PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSet);

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
    // We don't have predefined PSS RAW, so we build parameters manually.
    RsaSsaPssParameters pssParams =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();

    KeysetHandle privateHandle = KeysetHandle.generateNew(pssParams);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSet);

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
        GeneralSecurityException.class, () -> JwkSetConverter.fromPublicKeysetHandle(publicHandle));
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
        GeneralSecurityException.class, () -> JwkSetConverter.fromPublicKeysetHandle(publicHandle));
  }

  @Test
  public void testImportWithKidIgnoresKidAndImportsAsRaw() throws Exception {
    // Create a valid JWK but add a custom kid to it.
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(
            PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);

    JsonObject jsonKeyset = JsonParser.parse(jwkSet).getAsJsonObject();
    JsonArray jsonKeys = jsonKeyset.get("keys").getAsJsonArray();
    JsonObject jsonKey = jsonKeys.get(0).getAsJsonObject();
    jsonKey.addProperty("kid", "some-custom-kid-string");

    String jwkSetWithKid = jsonKeyset.toString();

    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSetWithKid);

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
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(invalidJwkSet));
  }

  @Test
  public void testImportMismatchedHashCurveThrows() throws Exception {
    // alg is ES256 (implies SHA256), but crv is P-384
    String mismatchedJwkSet =
        "{\"keys\": [{\"kty\": \"EC\", \"alg\": \"ES256\", \"crv\": \"P-384\", \"x\": \"fake\", \"y\": \"fake\"}]}";
    assertThrows(
        GeneralSecurityException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(mismatchedJwkSet));
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

    String jwkSet = JwkSetConverter.fromPublicKeysetHandle(publicHandle);
    KeysetHandle importedHandle = JwkSetConverter.toPublicKeysetHandle(jwkSet);

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
        () -> JwkSetConverter.fromPublicKeysetHandle(publicHandle));
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
}
