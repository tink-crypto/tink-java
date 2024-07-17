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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RsaSsaPssConscryptFipsTest {

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
      assertThat(RsaSsaPssSignConscrypt.create(privateKey)).isNotNull();
      assertThat(RsaSsaPssVerifyConscrypt.create(privateKey.getPublicKey())).isNotNull();
    } else {
      assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSignConscrypt.create(privateKey));
      assertThrows(
          GeneralSecurityException.class,
          () -> RsaSsaPssVerifyConscrypt.create(privateKey.getPublicKey()));
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

    assertThrows(GeneralSecurityException.class, () -> RsaSsaPssSignConscrypt.create(privateKey));
    assertThrows(
        GeneralSecurityException.class,
        () -> RsaSsaPssVerifyConscrypt.create(privateKey.getPublicKey()));
  }
}
