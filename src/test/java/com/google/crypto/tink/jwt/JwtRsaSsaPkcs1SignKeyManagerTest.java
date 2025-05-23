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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPkcs1SignKeyManager. */
@RunWith(Theories.class)
public class JwtRsaSsaPkcs1SignKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    JwtSignatureConfig.register();
  }

  @DataPoints("algorithmParam")
  public static final JwtRsaSsaPkcs1Parameters.Algorithm[] ALGO_PARAMETER =
      new JwtRsaSsaPkcs1Parameters.Algorithm[] {
        JwtRsaSsaPkcs1Parameters.Algorithm.RS256,
        JwtRsaSsaPkcs1Parameters.Algorithm.RS384,
        JwtRsaSsaPkcs1Parameters.Algorithm.RS512
      };

  @DataPoints("sizes")
  public static final int[] SIZE = new int[] {2048, 3072, 4096};

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_RS256_2048_F4",
        "JWT_RS256_2048_F4_RAW",
        "JWT_RS256_3072_F4",
        "JWT_RS256_3072_F4_RAW",
        "JWT_RS384_3072_F4",
        "JWT_RS384_3072_F4_RAW",
        "JWT_RS512_4096_F4",
        "JWT_RS512_4096_F4_RAW",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templates") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  // This test needs to create several new keys, which is expensive. Therefore, we only do it for
  // one set of parameters.
  @Test
  public void createKey_alwaysNewElement_ok()
      throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPkcs1Parameters parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    Set<BigInteger> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      JwtRsaSsaPkcs1PrivateKey key =
          (JwtRsaSsaPkcs1PrivateKey) KeysetHandle.generateNew(parameters).getPrimary().getKey();
      keys.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      keys.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(2 * numTests);
  }

  @Test
  public void testJwtRsa2048AlgoRS256F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_RS256_2048_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_RS256_2048_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_RS512_4096_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_RS512_4096_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_RS384_3072_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_RS384_3072_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_RS256_3072_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_RS256_3072_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void createKeysetHandle_works() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("JWT_RS256_2048_F4"));
    
    com.google.crypto.tink.Key key = handle.getAt(0).getKey();
    assertThat(key).isInstanceOf(JwtRsaSsaPkcs1PrivateKey.class);
    JwtRsaSsaPkcs1PrivateKey jwtPrivateKey = (JwtRsaSsaPkcs1PrivateKey) key;

    assertThat(jwtPrivateKey.getParameters())
        .isEqualTo(
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4TemplateWithManager_ok() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    Parameters p = KeyTemplates.get("JWT_RS512_4096_F4").toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4TemplateWithManager_ok() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    Parameters p = KeyTemplates.get("JWT_RS384_3072_F4").toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4TemplateWithManager_ok() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    Parameters p = KeyTemplates.get("JWT_RS256_3072_F4").toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_success(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
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
    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherHandle = KeysetHandle.generateNew(template);
    JwtPublicKeyVerify otherVerifier =
        otherHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
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
    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
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
    JwtPublicKeySign signer =
        handle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
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
    String signature =
        Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  @Test
  public void createSignVerifyRaw_withDifferentHeaders() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtRsaSsaPkcs1PrivateKey key = (JwtRsaSsaPkcs1PrivateKey) handle.getAt(0).getKey();

    RsaSsaPkcs1Parameters nonJwtParameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey nonJwtPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(key.getPublicKey().getModulus())
            .build();
    RsaSsaPkcs1PrivateKey nonJwtPrivateKey =
        RsaSsaPkcs1PrivateKey.builder()
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
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "RS256");
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

    // invalid token with an unknown algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS255");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "kid" in the header is valid
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "RS256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtRsaSsaPkcs1PrivateKey key = (JwtRsaSsaPkcs1PrivateKey) handle.getAt(0).getKey();
    RsaSsaPkcs1Parameters nonJwtParameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey nonJwtPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(key.getPublicKey().getModulus())
            .build();
    RsaSsaPkcs1PrivateKey nonJwtPrivateKey =
        RsaSsaPkcs1PrivateKey.builder()
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

    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = key.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // normal, valid token
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", "RS256");
    normalHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "RS256");
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // invalid token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("alg", "PS256");
    headerWithBadAlg.addProperty("kid", kid);
    String tokenWithBadAlg = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithBadAlg, validator));

    // token with an unknown "kid" in the header is invalid
    JsonObject headerWithUnknownKid = new JsonObject();
    headerWithUnknownKid.addProperty("alg", "RS256");
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  /* Create a new keyset handle with the "custom_kid" value set. */
  private KeysetHandle withCustomKid(KeysetHandle keysetHandle, String customKid) throws Exception {
    JwtRsaSsaPkcs1PrivateKey originalPrivateKey =
        (JwtRsaSsaPkcs1PrivateKey) keysetHandle.getAt(0).getKey();
    JwtRsaSsaPkcs1Parameters customKidParameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setAlgorithm(originalPrivateKey.getParameters().getAlgorithm())
            .setModulusSizeBits(originalPrivateKey.getParameters().getModulusSizeBits())
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
            .build();
    com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PublicKey customKidPublicKey =
        com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(customKidParameters)
            .setModulus(originalPrivateKey.getPublicKey().getModulus())
            .setCustomKid(customKid)
            .build();
    JwtRsaSsaPkcs1PrivateKey customKidPrivateKey =
        JwtRsaSsaPkcs1PrivateKey.builder()
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
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid =
        withCustomKid(handleWithoutKid, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtPublicKeySign signerWithKid =
        handleWithKid.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeySign signerWithoutKid =
        handleWithoutKid.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
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
        handleWithoutKid
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify verifierWithKid =
        handleWithKid
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

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
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }

    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid = withCustomKid(handleWithoutKid, "kid");
    KeysetHandle handleWithWrongKid = withCustomKid(handleWithoutKid, "wrong kid");

    JwtPublicKeySign signerWithKid =
        handleWithKid.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        handleWithWrongKid
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void serializeAndDeserializePublicKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_RS256_2048_F4");
    KeysetHandle handle = KeysetHandle.generateNew(template).getPublicKeysetHandle();

    byte[] serializedKeyset = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void testKeyManagersRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"))
        .isNotNull();
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"))
        .isNotNull();
  }
}
