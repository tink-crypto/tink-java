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
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPssSignKeyManager. */
@RunWith(Theories.class)
public class JwtRsaSsaPssSignKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    JwtSignatureConfig.register();
  }

  @DataPoints("sizes")
  public static final int[] SIZE = new int[] {2048, 3072, 4096};

  @DataPoints("templates")
  public static final String[] TEMPLATES =
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
  public void createKey_alwaysNewElement_ok() throws Exception {
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPssParameters parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    Set<BigInteger> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      JwtRsaSsaPssPrivateKey key =
          (JwtRsaSsaPssPrivateKey) KeysetHandle.generateNew(parameters).getPrimary().getKey();
      keys.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      keys.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(2 * numTests);
  }

  @Test
  public void testJwtRsa2048AlgoRS256F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_PS256_2048_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_PS256_2048_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_PS512_4096_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_PS512_4096_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_PS384_3072_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_PS384_3072_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4Template_ok() throws Exception {
    assertThat(KeyTemplates.get("JWT_PS256_3072_F4").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
    assertThat(KeyTemplates.get("JWT_PS256_3072_F4_RAW").toParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build());
  }

  @Test
  public void createKeysetHandle_works() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("JWT_PS256_2048_F4"));

    com.google.crypto.tink.Key key = handle.getAt(0).getKey();
    assertThat(key).isInstanceOf(com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey.class);
    com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey jwtPrivateKey =
        (com.google.crypto.tink.jwt.JwtRsaSsaPssPrivateKey) key;

    assertThat(jwtPrivateKey.getParameters())
        .isEqualTo(
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
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

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_PS256_2048_F4_RAW");
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
                .getUntypedKeyManager(
                    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"))
        .isNotNull();
  }
}
