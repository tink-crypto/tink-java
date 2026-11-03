// Copyright 2023 Google Inc.
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtSignatureConfigTest. */
@RunWith(JUnit4.class)
public class JwtSignatureConfigTest {

  @BeforeClass
  public static void setup() {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // This test may be run without onlyFips turned on, in which case it is fine that installing
      // conscrypt fails.
    }
  }

  @Test
  public void failIfAndOnlyIfInInvalidFipsState() throws Exception {
    Assume.assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    boolean invalidFipsState = TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable();

    JwtEcdsaParameters es256Parameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtRsaSsaPkcs1Parameters rs256Parameters =
        JwtRsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
            .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
            .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();
    JwtRsaSsaPssParameters ps256Parameters =
        JwtRsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(JwtRsaSsaPssParameters.F4)
            .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
            .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .build();

    if (invalidFipsState) {
      assertThrows(GeneralSecurityException.class, JwtSignatureConfig::register);
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(es256Parameters, RegistryConfiguration.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(rs256Parameters, RegistryConfiguration.get()));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(ps256Parameters, RegistryConfiguration.get()));

    } else {
      JwtSignatureConfig.register();
      assertNotNull(KeysetHandle.generateNew(es256Parameters, RegistryConfiguration.get()));
      assertNotNull(KeysetHandle.generateNew(rs256Parameters, RegistryConfiguration.get()));
      assertNotNull(KeysetHandle.generateNew(ps256Parameters, RegistryConfiguration.get()));
    }
  }

  @Test
  public void generateJwtMlDsa_nonFips() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported() || TestUtil.isTsan()) {
      // createKey is too slow in Tsan.
      return;
    }

    JwtSignatureConfig.register();
    assertNotNull(
        KeysetHandle.generateNew(
            JwtMlDsaParameters.create(
                JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
                JwtMlDsaParameters.Algorithm.ML_DSA_44),
            RegistryConfiguration.get()));
  }
}
