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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.subtle.Base64;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPkcs1ConscryptFipsTest {

  @Before
  public void useConscrypt() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  private static final BigInteger EXPONENT = new BigInteger(1, Base64.urlSafeDecode("AQAB"));

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
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(parameters, null);
    RsaSsaPkcs1PublicKey publicKey = privateKey.getPublicKey();

    if (TinkFipsUtil.fipsModuleAvailable()) {
      assertThat(RsaSsaPkcs1SignJce.create(privateKey)).isNotNull();
      assertThat(RsaSsaPkcs1VerifyConscrypt.create(publicKey)).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1SignJce.create(privateKey));
      assertThrows(
          GeneralSecurityException.class, () -> RsaSsaPkcs1VerifyConscrypt.create(publicKey));
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
    RsaSsaPkcs1PrivateKey privateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor4096BitParameters(parameters, null);
    RsaSsaPkcs1PublicKey publicKey = privateKey.getPublicKey();

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPkcs1SignJce.create(privateKey));
    assertThrows(
        GeneralSecurityException.class, () -> RsaSsaPkcs1VerifyConscrypt.create(publicKey));
  }
}
