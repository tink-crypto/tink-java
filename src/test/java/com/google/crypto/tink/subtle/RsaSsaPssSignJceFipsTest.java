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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
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
public final class RsaSsaPssSignJceFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void create_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssTestUtil.privateKeyFor2048BitParameters(parameters, null);

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPssSignJce.create(privateKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSignJce.create(privateKey));
    }
  }

  @Test
  public void constructor_accepts2048ModulusIfFipsModuleIsAvailable() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssTestUtil.privateKeyFor2048BitParameters(parameters, null);
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
      assertThat(new RsaSsaPssSignJce(rsaPrivateCrtKey, HashType.SHA256, HashType.SHA256, 64))
          .isNotNull();
    } else {
      assertThrows(
          GeneralSecurityException.class,
          () -> new RsaSsaPssSignJce(rsaPrivateCrtKey, HashType.SHA256, HashType.SHA256, 64));
    }
  }

  @Test
  public void create_refuses4096Modulus() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssTestUtil.privateKeyFor4096BitParameters(parameters, null);

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSignJce.create(privateKey));
  }

  @Test
  public void constructor_refuses4096Modulus() throws Exception {
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(4096)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey privateKey =
        RsaSsaPssTestUtil.privateKeyFor4096BitParameters(parameters, null);
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
        () -> new RsaSsaPssSignJce(rsaPrivateCrtKey, HashType.SHA256, HashType.SHA256, 64));
  }
}
