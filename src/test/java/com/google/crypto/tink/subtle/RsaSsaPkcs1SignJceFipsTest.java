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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1SignJceFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void create_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(parameters, null);

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPkcs1SignJce.create(privateKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1SignJce.create(privateKey));
    }
  }

  @Test
  public void constructor_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(parameters, null);
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPrivateCrtKey rsaPrivateCrtKey =
        (RSAPrivateCrtKey)
            keyFactory.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    privateKey.getPublicKey().getModulus(),
                    privateKey.getPublicKey().getParameters().getPublicExponent(),
                    privateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(new RsaSsaPkcs1SignJce(rsaPrivateCrtKey, HashType.SHA256)).isNotNull();
    } else {
      assertThrows(
          GeneralSecurityException.class,
          () -> new RsaSsaPkcs1SignJce(rsaPrivateCrtKey, HashType.SHA256));
    }
  }

  @Test
  public void create_refuses4096Modulus() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(parameters, null);

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1SignJce.create(privateKey));
  }

  @Test
  public void constructor_refuses4096Modulus() throws Exception {
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(4096)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(parameters, null);
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPrivateCrtKey rsaPrivateCrtKey =
        (RSAPrivateCrtKey)
            keyFactory.generatePrivate(
                new RSAPrivateCrtKeySpec(
                    privateKey.getPublicKey().getModulus(),
                    privateKey.getPublicKey().getParameters().getPublicExponent(),
                    privateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeExponentP().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getPrimeExponentQ().getBigInteger(InsecureSecretKeyAccess.get()),
                    privateKey.getCrtCoefficient().getBigInteger(InsecureSecretKeyAccess.get())));
    assertThrows(
        GeneralSecurityException.class,
        () -> new RsaSsaPkcs1SignJce(rsaPrivateCrtKey, HashType.SHA256));
  }
}
