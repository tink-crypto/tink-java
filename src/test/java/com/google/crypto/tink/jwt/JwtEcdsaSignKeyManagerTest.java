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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.testing.TestUtil;
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

/** Unit tests for JwtEcdsaSignKeyManager. */
@RunWith(Theories.class)
public class JwtEcdsaSignKeyManagerTest {

  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
    SignatureConfig.register();
  }

  @DataPoints("parametersAlgos")
  public static final JwtEcdsaParameters.Algorithm[] PARAMETERS_ALGOS =
      new JwtEcdsaParameters.Algorithm[] {
        JwtEcdsaParameters.Algorithm.ES256,
        JwtEcdsaParameters.Algorithm.ES384,
        JwtEcdsaParameters.Algorithm.ES512
      };

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_ES256", "JWT_ES384_RAW", "JWT_ES512",
      };

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    int numKeys = 10;
    Parameters p = KeyTemplates.get("JWT_ES256").toParameters();
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtEcdsaPrivateKey key = (JwtEcdsaPrivateKey) KeysetHandle.generateNew(p).getAt(0).getKey();
      keys.add(key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testJwtES256RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .build());
  }

  @Test
  public void testJwtES384RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES384_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .build());
  }

  @Test
  public void testJwtES512RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES512_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .build());
  }

  @Test
  public void testJwtES256Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .build());
  }

  @Test
  public void testJwtES384Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES384");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .build());
  }

  @Test
  public void testJwtES512Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES512");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .build());
  }

  @Theory
  public void testTemplates(@FromDataPoints("templates") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void ignoredKidStrategy_createKeyWithoutIdRequirement_works() throws Exception {
    if (TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    Key unused = MutableKeyCreationRegistry.globalInstance().createKey(parameters, null);
  }

  @Test
  public void ignoredKidStrategy_createKeyWithIdRequirement_throws() throws Exception {
    if (TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> MutableKeyCreationRegistry.globalInstance().createKey(parameters, 123));
  }

  @Test
  public void base64KidStrategy_createKeyWithIdRequirement_works() throws Exception {
    if (TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    Key unused = MutableKeyCreationRegistry.globalInstance().createKey(parameters, 123);
  }

  @Test
  public void base64KidStrategy_createKeyWithoutIdRequirement_thows() throws Exception {
    if (TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> MutableKeyCreationRegistry.globalInstance().createKey(parameters, null));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_success(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
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
                .allowMissingExpiration()
                .expectTypeHeader("typeHeader")
                .build());
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void testKeyManagersRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"))
        .isNotNull();
  }
}
