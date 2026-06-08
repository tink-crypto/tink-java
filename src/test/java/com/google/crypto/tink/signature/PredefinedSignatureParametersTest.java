// Copyright 2023 Google LLC
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
import static com.google.common.truth.TruthJUnit.assume;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.signature.internal.SlhDsaVerifyConscrypt;
import com.google.crypto.tink.testing.TestUtil;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class PredefinedSignatureParametersTest {
  private static boolean conscryptIsAvailable() {
    try {
      return Conscrypt.isAvailable();
    } catch (Throwable e) {
      return false;
    }
  }

  @BeforeClass
  public static void setUp() throws Exception {
    SignatureConfig.register();
    if (!TestUtil.isAndroid() && conscryptIsAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
      MlDsaSignKeyManager.registerPair();
      SlhDsaSignKeyManager.registerPair();
    }
  }

  @DataPoints("AllClassicalParameters")
  public static final SignatureParameters[] TEMPLATES =
      new SignatureParameters[] {
        PredefinedSignatureParameters.ECDSA_P256,
        PredefinedSignatureParameters.ECDSA_P256_NO_PREFIX,
        PredefinedSignatureParameters.ECDSA_P384,
        PredefinedSignatureParameters.ECDSA_P521,
        PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363,
        PredefinedSignatureParameters.ECDSA_P384_IEEE_P1363,
        PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX,
        PredefinedSignatureParameters.ECDSA_P521_IEEE_P1363,
        PredefinedSignatureParameters.ED25519,
        PredefinedSignatureParameters.ED25519WithRawOutput,
        PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4,
        PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX,
        PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4,
        PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
        PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
      };

  @Theory
  public void testClassicalInstantiation(
      @FromDataPoints("AllClassicalParameters") SignatureParameters parameters) throws Exception {
    if (TestUtil.isTsan()) {
      assume().that(parameters).isInstanceOf(Ed25519Parameters.class);
    }

    Key key = KeysetHandle.generateNew(parameters).getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void testClassicalTypes() throws Exception {
    assertThat(PredefinedSignatureParameters.ECDSA_P256).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P256_NO_PREFIX).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P384).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P521).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P384_IEEE_P1363).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX).isNotNull();
    assertThat(PredefinedSignatureParameters.ECDSA_P521_IEEE_P1363).isNotNull();
    assertThat(PredefinedSignatureParameters.ED25519).isNotNull();
    assertThat(PredefinedSignatureParameters.ED25519WithRawOutput).isNotNull();
    assertThat(PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4).isNotNull();
    assertThat(PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX)
        .isNotNull();
    assertThat(PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4).isNotNull();
    assertThat(PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4).isNotNull();
    assertThat(PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4).isNotNull();
  }

  @DataPoints("AllPqcParameters")
  public static final SignatureParameters[] PQC_TEMPLATES =
      new SignatureParameters[] {
        PredefinedSignatureParameters.ML_DSA_65,
        PredefinedSignatureParameters.ML_DSA_65_NO_PREFIX,
        PredefinedSignatureParameters.SLH_DSA_SHA2_128S,
        PredefinedSignatureParameters.SLH_DSA_SHA2_128S_NO_PREFIX,
      };

  @Theory
  public void testPqcInstantiation(
      @FromDataPoints("AllPqcParameters") SignatureParameters parameters) throws Exception {
    if (TestUtil.isAndroid() || !conscryptIsAvailable()) {
      System.out.println(
          "testPqcInstantiation doesn't work on Android or without Conscrypt, skipping");
      return;
    }
    if (!SlhDsaVerifyConscrypt.isSupported() || !MlDsaVerifyConscrypt.isSupported()) {
      System.out.println(
          "testPqcInstantion requires a version of Conscrypt that supports SLH-DSA and ML-DSA.");
      return;
    }

    Key key = KeysetHandle.generateNew(parameters).getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(parameters);
  }

  @Test
  public void testPqcTypes() throws Exception {
    assertThat(PredefinedSignatureParameters.ML_DSA_65).isNotNull();
    assertThat(PredefinedSignatureParameters.ML_DSA_65_NO_PREFIX).isNotNull();
    assertThat(PredefinedSignatureParameters.SLH_DSA_SHA2_128S).isNotNull();
    assertThat(PredefinedSignatureParameters.SLH_DSA_SHA2_128S_NO_PREFIX).isNotNull();
  }
}
