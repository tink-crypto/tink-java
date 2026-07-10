// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt.subtle;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.jwt.JwtInvalidException;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtRsaSsaPssParameters;
import com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey;
import com.google.crypto.tink.jwt.JwtRsaSsaPssPublicKey;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPssSignKeyManager. */
@RunWith(Theories.class)
public class JwtRsaSsaPssPublicKeySignTest {

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    JwtSignatureConfig.register();
  }

  @DataPoints("templates")
  public static final String[] templates =
      new String[] {
        "JWT_PS256_2048_F4_RAW",
        "JWT_PS256_2048_F4",
        "JWT_PS256_3072_F4_RAW",
        "JWT_PS256_3072_F4",
        "JWT_PS384_3072_F4_RAW",
        "JWT_PS384_3072_F4",
        "JWT_PS512_4096_F4_RAW",
        "JWT_PS512_4096_F4",
      };

  @Theory
  public void createSignVerify_success(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    JwtPublicKeySign signer = JwtRsaSsaPssPublicKeySign.create(key);
    JwtPublicKeyVerify verifier = JwtRsaSsaPssPublicKeyVerify.create(key.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerifyDifferentKey_throw(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeyTemplate template = KeyTemplates.get(templateName);
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    JwtPublicKeySign signer = JwtRsaSsaPssPublicKeySign.create(key);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherHandle = KeysetHandle.generateNew(template);
    JwtRsaSsaPssPrivateKey otherKey = (JwtRsaSsaPssPrivateKey) otherHandle.getAt(0).getKey();
    JwtPublicKeyVerify otherVerifier = JwtRsaSsaPssPublicKeyVerify.create(otherKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_header_modification_throw(
      @FromDataPoints("templates") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    JwtPublicKeySign signer = JwtRsaSsaPssPublicKeySign.create(key);
    JwtPublicKeyVerify verifier = JwtRsaSsaPssPublicKeyVerify.create(key.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_payload_modification_throw(
      @FromDataPoints("templates") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    JwtPublicKeySign signer = JwtRsaSsaPssPublicKeySign.create(key);
    JwtPublicKeyVerify verifier = JwtRsaSsaPssPublicKeyVerify.create(key.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  private static String generateSignedCompact(
      PublicKeySign rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature = Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  @Test
  public void createSignVerify_withDifferentHeaders() throws Exception {
    assumeFalse(TestUtil.isTsan()); // creating keys is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_PS256_2048_F4_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    RsaSsaPssParameters nonJwtParameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPublicKey nonJwtPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(key.getPublicKey().getModulus())
            .build();
    RsaSsaPssPrivateKey nonJwtPrivateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(key.getPrimeP(), key.getPrimeQ())
            .setPrivateExponent(key.getPrivateExponent())
            .setPrimeExponents(key.getPrimeExponentP(), key.getPrimeExponentQ())
            .setCrtCoefficient(key.getCrtCoefficient())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JwtPublicKeyVerify verifier = JwtRsaSsaPssPublicKeyVerify.create(key.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "PS256");
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    Object unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "kid" in the header is valid
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "PS256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    assumeFalse(TestUtil.isTsan()); // creating keys is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_PS256_2048_F4");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    JwtRsaSsaPssPrivateKey key = (JwtRsaSsaPssPrivateKey) handle.getAt(0).getKey();
    RsaSsaPssParameters nonJwtParameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setSaltLengthBytes(32)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPublicKey nonJwtPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(key.getPublicKey().getModulus())
            .build();
    RsaSsaPssPrivateKey nonJwtPrivateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(key.getPrimeP(), key.getPrimeQ())
            .setPrivateExponent(key.getPrivateExponent())
            .setPrimeExponents(key.getPrimeExponentP(), key.getPrimeExponentQ())
            .setCrtCoefficient(key.getCrtCoefficient())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JwtPublicKeyVerify verifier = JwtRsaSsaPssPublicKeyVerify.create(key.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = key.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token
    JsonObject validHeader = new JsonObject();
    validHeader.addProperty("alg", "PS256");
    validHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, validHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "PS256");
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // invalid token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("alg", "RS256");
    headerWithBadAlg.addProperty("kid", kid);
    String tokenWithBadAlg = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithBadAlg, validator));

    // token with an unknown "kid" in the header is invalid
    JsonObject headerWithUnknownKid = new JsonObject();
    headerWithUnknownKid.addProperty("alg", "PS256");
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  /* Create a new keyset handle with the "custom_kid" value set. */
  private KeysetHandle withCustomKid(KeysetHandle keysetHandle, String customKid) throws Exception {
    JwtRsaSsaPssPrivateKey originalPrivateKey =
        (JwtRsaSsaPssPrivateKey) keysetHandle.getAt(0).getKey();
    JwtRsaSsaPssParameters customKidParameters =
        JwtRsaSsaPssParameters.builder()
            .setAlgorithm(originalPrivateKey.getParameters().getAlgorithm())
            .setModulusSizeBits(originalPrivateKey.getParameters().getModulusSizeBits())
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
            .build();
    JwtRsaSsaPssPublicKey customKidPublicKey =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(customKidParameters)
            .setModulus(originalPrivateKey.getPublicKey().getModulus())
            .setCustomKid(customKid)
            .build();
    JwtRsaSsaPssPrivateKey customKidPrivateKey =
        JwtRsaSsaPssPrivateKey.builder()
            .setPublicKey(customKidPublicKey)
            .setPrimes(originalPrivateKey.getPrimeP(), originalPrivateKey.getPrimeQ())
            .setPrivateExponent(originalPrivateKey.getPrivateExponent())
            .setPrimeExponents(
                originalPrivateKey.getPrimeExponentP(), originalPrivateKey.getPrimeExponentQ())
            .setCrtCoefficient(originalPrivateKey.getCrtCoefficient())
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(customKidPrivateKey).makePrimary().withRandomId())
        .build();
  }

  @Test
  public void signAndVerifyWithCustomKid() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_PS256_2048_F4_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid =
        withCustomKid(handleWithoutKid, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtRsaSsaPssPrivateKey keyWithKid = (JwtRsaSsaPssPrivateKey) handleWithKid.getAt(0).getKey();
    JwtPublicKeySign signerWithKid = JwtRsaSsaPssPublicKeySign.create(keyWithKid);
    JwtRsaSsaPssPrivateKey keyWithoutKid =
        (JwtRsaSsaPssPrivateKey) handleWithoutKid.getAt(0).getKey();
    JwtPublicKeySign signerWithoutKid = JwtRsaSsaPssPublicKeySign.create(keyWithoutKid);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo("Lorem ipsum dolor sit amet, consectetur adipiscing elit");
    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid =
        JwtRsaSsaPssPublicKeyVerify.create(keyWithoutKid.getPublicKey());
    JwtPublicKeyVerify verifierWithKid =
        JwtRsaSsaPssPublicKeyVerify.create(keyWithKid.getPublicKey());

    // Even if custom_kid is set, we don't require a "kid" in the header.
    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");

    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
  }

  @Test
  public void signAndVerifyWithWrongCustomKid_fails() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.

    KeyTemplate template = KeyTemplates.get("JWT_PS256_2048_F4_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid = withCustomKid(handleWithoutKid, "kid");
    KeysetHandle handleWithWrongKid = withCustomKid(handleWithoutKid, "wrong kid");

    JwtRsaSsaPssPrivateKey keyWithKid = (JwtRsaSsaPssPrivateKey) handleWithKid.getAt(0).getKey();
    JwtPublicKeySign signerWithKid = JwtRsaSsaPssPublicKeySign.create(keyWithKid);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtRsaSsaPssPrivateKey keyWithWrongKid =
        (JwtRsaSsaPssPrivateKey) handleWithWrongKid.getAt(0).getKey();
    JwtPublicKeyVerify verifierWithWrongKid =
        JwtRsaSsaPssPublicKeyVerify.create(keyWithWrongKid.getPublicKey());

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }
}
