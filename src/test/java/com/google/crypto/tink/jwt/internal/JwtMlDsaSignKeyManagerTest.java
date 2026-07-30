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

package com.google.crypto.tink.jwt.internal;

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
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link JwtMlDsaSignKeyManager}. */
@RunWith(Theories.class)
public class JwtMlDsaSignKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will fail or be skipped.
    }
    JwtSignatureConfig.register();
    JwtMlDsaSignKeyManager.registerPair(/* newKeyAllowed= */ true);
  }

  private static class TestVector {
    final String template;
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Integer idRequirement;

    TestVector(
        String template,
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        @Nullable Integer idRequirement) {
      this.template = template;
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.idRequirement = idRequirement;
    }
  }

  @DataPoints("testVectors")
  public static final TestVector[] testVectors = {
    new TestVector(
        "JWT_ML_DSA_44",
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        "JWT_ML_DSA_44_RAW",
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* idRequirement= */ null),
    new TestVector(
        "JWT_ML_DSA_65",
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        "JWT_ML_DSA_65_RAW",
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* idRequirement= */ null),
    new TestVector(
        "JWT_ML_DSA_87",
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        "JWT_ML_DSA_87_RAW",
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* idRequirement= */ null),
  };

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }

    int numKeys = 10;
    Parameters p = KeyTemplates.get("JWT_ML_DSA_44").toParameters();
    Set<Bytes> keys = new HashSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtMlDsaPrivateKey key = (JwtMlDsaPrivateKey) KeysetHandle.generateNew(p).getAt(0).getKey();
      keys.add(Bytes.copyFrom(key.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Theory
  public void namedParameters(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    KeyTemplate template = KeyTemplates.get(testVector.template);
    assertThat(template.toParameters())
        .isEqualTo(JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm));
  }

  @Theory
  public void createKeyFromTemplate(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(testVector.template));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(testVector.template).toParameters());
  }

  @Theory
  public void createKeyFromParameters(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters = JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);
    Key key =
        MutableKeyCreationRegistry.globalInstance().createKey(parameters, testVector.idRequirement);
    assertThat(key).isNotNull();
  }

  @Test
  public void ignoredKidStrategy_createKeyWithIdRequirement_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    assertThrows(
        GeneralSecurityException.class,
        () -> MutableKeyCreationRegistry.globalInstance().createKey(parameters, 123));
  }

  @Test
  public void base64KidStrategy_createKeyWithoutIdRequirement_thows() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }
    Parameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);
    assertThrows(
        GeneralSecurityException.class,
        () -> MutableKeyCreationRegistry.globalInstance().createKey(parameters, null));
  }

  @Theory
  public void createSignVerify_success(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }

    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(testVector.template));
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
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }

    KeyTemplate template = KeyTemplates.get("JWT_ML_DSA_44_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            handle, InsecureSecretKeyAccess.get(), RegistryConfiguration.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeyset, InsecureSecretKeyAccess.get(), RegistryConfiguration.get());
    assertTrue(parsed.equalsKeyset(handle));
  }
}
