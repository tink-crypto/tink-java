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

package com.google.crypto.tink.jwt.subtle;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.CUSTOM_KID_VALUE;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.createJwtEcdsaPrivateKeys;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.generateSignedCompact;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.jwtCustomKidPrivateKeyMap;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.jwtRawPrivateKeyMap;
import static com.google.crypto.tink.jwt.internal.testing.JwtSignatureTestUtil.jwtWrongKidPrivateKeyMap;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtInvalidException;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignaturePrivateKey;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class JwtEcdsaPublicKeySignTest {

  @DataPoints("jwtPrivateKeys")
  public static final List<JwtSignaturePrivateKey> jwtPrivateKeys = createJwtEcdsaPrivateKeys();

  @DataPoints("jwtAlgorithms")
  public static final String[] jwtAlgorithms = new String[] {"ES256", "ES384", "ES512"};

  // Ecdsa-specific tests
  private static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.CurveType.NIST_P256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.CurveType.NIST_P384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static EcdsaParameters.HashType getEcdsaHash(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @Theory
  public void signVerifyRaw_differentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                == JwtEcdsaParameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getEcdsaHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner = EcdsaSignJce.create(nonJwtPrivateKey);

    JsonObject payload = new JsonObject();
    payload.addProperty("jid", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier = JwtEcdsaPublicKeyVerify.create(jwtEcdsaPrivateKey.getPublicKey());

    // Valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String normalSignedCompact = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    unused =
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

    // for raw keys, the validation should work even if a "kid" header is present.
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Theory
  public void signVerifyTink_differentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                != JwtEcdsaParameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getEcdsaHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner = EcdsaSignJce.create(nonJwtPrivateKey);

    String kid = jwtEcdsaPrivateKey.getPublicKey().getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier = JwtEcdsaPublicKeyVerify.create(jwtEcdsaPrivateKey.getPublicKey());

    // Normal, valid signed token.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    normalHeader.addProperty("kid", kid);
    String normalToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in the header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("kid", kid);
    headerWithBadAlg.addProperty(
        "alg",
        // "RS{256,384,512}"
        new StringBuilder(jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName())
            .replace(0, 1, "R")
            .toString());
    String badAlgToken = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(badAlgToken, validator));
  }

  @Theory
  public void signVerify_works(@FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key)
      throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    JwtEcdsaPrivateKey jwtPrivateKey = (JwtEcdsaPrivateKey) key;
    JwtPublicKeySign signer = JwtEcdsaPublicKeySign.create(jwtPrivateKey);
    JwtPublicKeyVerify verifier = JwtEcdsaPublicKeyVerify.create(jwtPrivateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .allowMissingExpiration()
                .expectTypeHeader("typeHeader")
                .build());

    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  @Theory
  public void signVerify_differentKey_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    JwtEcdsaPrivateKey jwtPrivateKey = (JwtEcdsaPrivateKey) key;
    JwtPublicKeySign signer = JwtEcdsaPublicKeySign.create(jwtPrivateKey);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    JwtEcdsaPrivateKey otherPrivateKey;
    if (key.equalsKey(jwtPrivateKeys.get(0)) || key.equalsKey(jwtPrivateKeys.get(1))) {
      otherPrivateKey = (JwtEcdsaPrivateKey) jwtPrivateKeys.get(2);
    } else {
      otherPrivateKey = (JwtEcdsaPrivateKey) jwtPrivateKeys.get(0);
    }
    JwtPublicKeyVerify otherVerifier = JwtEcdsaPublicKeyVerify.create(otherPrivateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Theory
  public void signVerify_headerModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    JwtEcdsaPrivateKey jwtPrivateKey = (JwtEcdsaPrivateKey) key;
    JwtPublicKeySign signer = JwtEcdsaPublicKeySign.create(jwtPrivateKey);
    JwtPublicKeyVerify verifier = JwtEcdsaPublicKeyVerify.create(jwtPrivateKey.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("issuer").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Theory
  public void signVerify_payloadModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    JwtEcdsaPrivateKey jwtPrivateKey = (JwtEcdsaPrivateKey) key;
    JwtPublicKeySign signer = JwtEcdsaPublicKeySign.create(jwtPrivateKey);
    JwtPublicKeyVerify verifier = JwtEcdsaPublicKeyVerify.create(jwtPrivateKey.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Theory
  public void signVerify_customKid_works(
      @FromDataPoints("jwtAlgorithms") String algorithm) throws Exception {
    JwtEcdsaPrivateKey jwtRawPrivateKey = (JwtEcdsaPrivateKey) jwtRawPrivateKeyMap.get(algorithm);
    JwtEcdsaPrivateKey jwtCustomKidPrivateKey = (JwtEcdsaPrivateKey) jwtCustomKidPrivateKeyMap.get(algorithm);

    JwtPublicKeySign signerWithKid = JwtEcdsaPublicKeySign.create(jwtCustomKidPrivateKey);
    JwtPublicKeySign signerWithoutKid = JwtEcdsaPublicKeySign.create(jwtRawPrivateKey);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo(CUSTOM_KID_VALUE);
    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid = JwtEcdsaPublicKeyVerify.create(jwtRawPrivateKey.getPublicKey());
    JwtPublicKeyVerify verifierWithKid = JwtEcdsaPublicKeyVerify.create(jwtCustomKidPrivateKey.getPublicKey());

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

  @Theory
  public void signVerify_wrongCustomKid_throws(
      @FromDataPoints("jwtAlgorithms") String algorithm)
      throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan. Similar functionality is tested in the other tests.
      return;
    }

    JwtEcdsaPrivateKey customKidKey = (JwtEcdsaPrivateKey) jwtCustomKidPrivateKeyMap.get(algorithm);
    JwtEcdsaPrivateKey wrongKidKey = (JwtEcdsaPrivateKey) jwtWrongKidPrivateKeyMap.get(algorithm);

    JwtPublicKeySign signerWithKid = JwtEcdsaPublicKeySign.create(customKidKey);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid = JwtEcdsaPublicKeyVerify.create(wrongKidKey.getPublicKey());

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }
}
