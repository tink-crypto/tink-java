// Copyright 2024 Google
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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1VerifyJceFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  // Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
  private static final BigInteger EXPONENT = new BigInteger(1, Base64.urlSafeDecode("AQAB"));
  static final BigInteger MODULUS_2048 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy"
                  + "O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP"
                  + "8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0"
                  + "Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X"
                  + "OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1"
                  + "_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"));

  // Test vector from Wycheproof's testvectors_v1/rsa_pkcs1_4096_test.json.
  static final BigInteger MODULUS_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkr"
                  + "xcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKK"
                  + "iroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvp"
                  + "tGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-"
                  + "cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7K"
                  + "UiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgs"
                  + "l46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12"
                  + "ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1w"
                  + "y0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd"
                  + "2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju"
                  + "0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7O"
                  + "Nfg9Y2281av0hToFHblNUEU"));

  @Test
  public void create_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPkcs1ProtoSerialization.register();
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS_2048).build();

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPkcs1VerifyJce.create(publicKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1VerifyJce.create(publicKey));
    }
  }

  @Test
  public void constructor_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(MODULUS_2048, EXPONENT));

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA256)).isNotNull();
    } else {
      assertThrows(
          GeneralSecurityException.class,
          () -> new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA256));
    }
  }

  @Test
  public void create_refusesNon2048Non3072Modulus() throws Exception {
    RsaSsaPkcs1ProtoSerialization.register();
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(EXPONENT)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey publicKey =
        RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(MODULUS_4096).build();

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1VerifyJce.create(publicKey));
  }

  @Test
  public void constructor_refusesNon2048Non3072Modulus() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(MODULUS_4096, EXPONENT));

    assertThrows(
        GeneralSecurityException.class, () -> new RsaSsaPkcs1VerifyJce(publicKey, HashType.SHA256));
  }
}
