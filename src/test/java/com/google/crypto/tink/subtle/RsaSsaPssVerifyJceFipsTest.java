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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
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
public final class RsaSsaPssVerifyJceFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  private static final BigInteger EXPONENT = new BigInteger("010001", 16);

  // Test vector from Wycheproof's testvectors rsa_pss_2048_sha256_mgf1_32_test.json
  static final BigInteger MODULUS_2048 =
      new BigInteger(
          "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5",
          16);

  // Test vector from Wycheproof's testvectors rsa_pss_3072_sha256_mgf1_32_test.json
  static final BigInteger MODULUS_3072 =
      new BigInteger(
          "00c6fe23792566023c265287c5ac6f71541c0994d11d059ee6403986efa21c24b51bd91d8862f9df79a4e328e3e27c83df260b25a9b43420affc44b51e8d7525b6f29c372a405104732007527a62ed82fac73f4892a80e09682a41a58cd347017f3be7d801334f92d9321aafd53b51bffabfc752cfccae0b1ee03bdaff9e428cc1c117f1ac96b4fe23f8c23e6381186a66fd59289339ae55c4bcdadbff84abdaa532240d4e1d28b2d0481dadd3b246557ca8fe18092817730b39e6ee378ffcc85b19ffdc916a9b991a6b66d4a9c7bab5f5e7a3722101142e7a4108c15d573b15289e07e46eaea07b42c2abcba330e99554b4656165bb4c0db2b6393a07eca575c51a93c4e15bdb0f747909447e3efe34c67ca8954b530e56a20a1b6d84d45ed1bcd3aa58ec06f184ee5857aaa819e1cca9a26f4e28d6b977d33916db9896d252d1afa762e287cb0d384cc75bfe53f4e922d02dd0a481c042e2d306b4b3c189371e575b25e0005a164cf69dd0976e4d5be476806ea6be6084e71ab4f5ac5c1b1203",
          16);

  // Test vector from Wycheproof's testvectors rsa_pss_4096_sha256_mgf1_32_test.json
  static final BigInteger MODULUS_4096 =
      new BigInteger(
          "00956353ecb7561945dc5544e4602466078c93f28507701ffd39e2a9813c8ac8740e6ad61c955d484e513b3dcea527e001a018ee2c207c1806a96763280236cd3c820dff79837c9b709cb4b522d3ddbc9192242259c43be75ea244d37ccfa8a4c75024a2cf7cc76e842ea69cc7ca1227405b070047387a5068e4976e4b8ed5f9aadd7b4db024fbb8d7bd8a040d8f6610c1c6eb1d4b606dfd182235d0360880304d5a750603af0c424b8c8e6dbc12c3697d2d609c97547e774e2e362ea96d1690dc9432112c535258b3db2c4c32ad510d6c07ad0788357883869efb8b629298724847925cf42b34386be700f02903db5852276bee2370941f397bdc3905e30964a0b5e73602703340960c3ed6078263b611f197955fecce4b9a32e43cd1d2e5e87c4ceb65edc8853a7ee31d28e16e5adffb8ac7b760fbfc63d5f174f4d0936461dbb12c964a6b6d6cee752e5fca1ab4a9fd238dd3e8860a1d763d2019f9e7b99ed7666d4e038710f90e0093bc566987d6c0092f571376e705b342d066c54e6e2578927b92c1f0928de44e9a6e1f49b907c6aa4f605ec9c398d55df81c67373b03cc8110162fb417f96fd321048647dfcbb392455115cd912ea83351853e6a185284648842adcbd25e67174a3b93b8a64ce2ce9de0e8577b8b662ce32e2565782665dd38e5bb5fcc4fe12e4320dab7773b545a09c6d39d9dbad459f21f3e624ee6ed",
          16);

  @Test
  public void create_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPssProtoSerialization.register();
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS_2048).build();

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPssVerifyJce.create(publicKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssVerifyJce.create(publicKey));
    }
  }

  @Test
  public void constructor_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(MODULUS_2048, EXPONENT));

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(new RsaSsaPssVerifyJce(publicKey, HashType.SHA256, HashType.SHA256, 64))
          .isNotNull();
    } else {
      assertThrows(
          GeneralSecurityException.class,
          () -> new RsaSsaPssVerifyJce(publicKey, HashType.SHA256, HashType.SHA256, 64));
    }
  }

  @Test
  public void create_accepts3072ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPssProtoSerialization.register();
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS_3072).build();

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPssVerifyJce.create(publicKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssVerifyJce.create(publicKey));
    }
  }

  @Test
  public void constructor_accepts3072ModulusIfFipsModuleIsAvailable() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(MODULUS_3072, EXPONENT));

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(new RsaSsaPssVerifyJce(publicKey, HashType.SHA256, HashType.SHA256, 64))
          .isNotNull();
    } else {
      assertThrows(
          GeneralSecurityException.class,
          () -> new RsaSsaPssVerifyJce(publicKey, HashType.SHA256, HashType.SHA256, 64));
    }
  }

  @Test
  public void create_refuses4096Modulus() throws Exception {
    RsaSsaPssProtoSerialization.register();
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(EXPONENT)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(64)
            .build();
    RsaSsaPssPublicKey publicKey =
        RsaSsaPssPublicKey.builder().setParameters(parameters).setModulus(MODULUS_4096).build();

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPssVerifyJce.create(publicKey));
  }

  @Test
  public void constructor_refuses4096Modulus() throws Exception {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey) keyFactory.generatePublic(new RSAPublicKeySpec(MODULUS_4096, EXPONENT));

    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPssVerifyJce(publicKey, HashType.SHA256, HashType.SHA256, 64));
  }
}
