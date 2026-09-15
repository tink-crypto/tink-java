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

package com.google.crypto.tink.jwt.subtle;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.jwt.JwtInvalidException;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaSignConscrypt;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.testing.MlDsaTestUtil;
import com.google.crypto.tink.subtle.Base64;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Optional;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link JwtMlDsaPublicKeySign} and {@link JwtMlDsaPublicKeyVerify}. */
@RunWith(Theories.class)
public final class JwtMlDsaPublicKeySignVerifyTest {

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will be skipped.
    }
  }

  private static final MlDsaPrivateKey MLDSA_44_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_44,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();

  private static final MlDsaPrivateKey MLDSA_65_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_65,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();
  private static final MlDsaPrivateKey MLDSA_87_KEY =
      (MlDsaPrivateKey)
          MlDsaTestUtil.getMlDsaValidSignatureTestVector(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_87,
                      MlDsaParameters.Variant.NO_PREFIX))
              .getPrivateKey();

  public static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Optional<String> kid;
    final JwtMlDsaPrivateKey privateKey;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        Optional<String> kid,
        @Nullable Integer idRequirement,
        MlDsaPrivateKey mlDsaPrivateKey) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.kid = kid;

      try {
        JwtMlDsaParameters parameters = JwtMlDsaParameters.create(kidStrategy, algorithm);
        JwtMlDsaPublicKey.Builder builder =
            JwtMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setPublicKeyBytes(mlDsaPrivateKey.getPublicKey().getSerializedPublicKey());
        if (idRequirement != null) {
          builder.setIdRequirement(idRequirement);
        }
        if (kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
          builder.setCustomKid(kid.get());
        }
        JwtMlDsaPublicKey publicKey = builder.build();
        this.privateKey = JwtMlDsaPrivateKey.create(publicKey, mlDsaPrivateKey.getPrivateSeed());
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  @DataPoints("testVectors")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944,
        MLDSA_44_KEY),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944,
        MLDSA_65_KEY),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null,
        MLDSA_65_KEY),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null,
        MLDSA_87_KEY),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.of("custom_kid_87"),
        /* idRequirement= */ null,
        MLDSA_87_KEY),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("custom_kid_44"),
        /* idRequirement= */ null,
        MLDSA_44_KEY),
  };

  @Theory
  public void createSignVerify_succeeds(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVector.privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVector.privateKey.getPublicKey());
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

  @Test
  public void createSignVerify_differentKey_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    JwtPublicKeyVerify otherVerifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[1].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Test
  public void createSignVerify_headerModification_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
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

  @Test
  public void createSignVerify_payloadModification_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
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
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    PublicKeySign nonJwtSigner =
        MlDsaSignConscrypt.create(testVectors[2].privateKey.getMlDsaPrivateKey());
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[2].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "ML-DSA-65");
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
    unknownKidHeader.addProperty("alg", "ML-DSA-65");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    PublicKeySign nonJwtSigner =
        MlDsaSignConscrypt.create(testVectors[0].privateKey.getMlDsaPrivateKey());
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = testVectors[0].privateKey.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token
    JsonObject validHeader = new JsonObject();
    validHeader.addProperty("alg", "ML-DSA-44");
    validHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, validHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "ML-DSA-44");
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
    headerWithUnknownKid.addProperty("alg", "ML-DSA-44");
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  private static JwtMlDsaPrivateKey withCustomKid(JwtMlDsaPrivateKey privateKey, String customKid)
      throws GeneralSecurityException {
    JwtMlDsaParameters customKidParameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, privateKey.getParameters().getAlgorithm());
    JwtMlDsaPublicKey customKidPublicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(customKidParameters)
            .setPublicKeyBytes(
                privateKey.getPublicKey().getMlDsaPublicKey().getSerializedPublicKey())
            .setCustomKid(customKid)
            .build();
    return JwtMlDsaPrivateKey.create(customKidPublicKey, privateKey.getPrivateSeed());
  }

  private static JwtMlDsaPrivateKey withIgnoredKid(JwtMlDsaPrivateKey privateKey)
      throws GeneralSecurityException {
    JwtMlDsaParameters ignoredKidParameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, privateKey.getParameters().getAlgorithm());
    JwtMlDsaPublicKey ignoredKidPublicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(ignoredKidParameters)
            .setPublicKeyBytes(
                privateKey.getPublicKey().getMlDsaPublicKey().getSerializedPublicKey())
            .build();
    return JwtMlDsaPrivateKey.create(ignoredKidPublicKey, privateKey.getPrivateSeed());
  }

  @Test
  public void signAndVerifyWithCustomKid() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtMlDsaPrivateKey keyWithoutKid = withIgnoredKid(testVectors[0].privateKey);
    JwtMlDsaPrivateKey keyWithKid =
        withCustomKid(
            testVectors[0].privateKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtPublicKeySign signerWithKid = JwtMlDsaPublicKeySign.create(keyWithKid);
    JwtPublicKeySign signerWithoutKid = JwtMlDsaPublicKeySign.create(keyWithoutKid);
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
        JwtMlDsaPublicKeyVerify.create(keyWithoutKid.getPublicKey());
    JwtPublicKeyVerify verifierWithKid = JwtMlDsaPublicKeyVerify.create(keyWithKid.getPublicKey());

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
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtMlDsaPrivateKey keyWithKid = withCustomKid(testVectors[0].privateKey, "kid");
    JwtMlDsaPrivateKey keyWithWrongKid = withCustomKid(testVectors[0].privateKey, "wrong kid");

    JwtPublicKeySign signerWithKid = JwtMlDsaPublicKeySign.create(keyWithKid);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        JwtMlDsaPublicKeyVerify.create(keyWithWrongKid.getPublicKey());

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void throwsIfMlDsaNotSupported() throws Exception {
    assumeFalse(MlDsaVerifyConscrypt.isSupported());

    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaPublicKeySign.create(testVectors[0].privateKey));
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey()));
  }
}
