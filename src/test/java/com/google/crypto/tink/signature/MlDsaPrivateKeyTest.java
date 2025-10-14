// Copyright 2025 Google LLC
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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MlDsaPrivateKeyTest {

  private static final int MLDSA65_PUBLIC_KEY_BYTES = 1952;
  private static final int MLDSA_SEED_BYTES = 32;

  private static final MlDsaParameters NO_PREFIX_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX);
  private static final MlDsaParameters TINK_PARAMS =
      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.TINK);

  private static final Bytes FAKE_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode("01".repeat(MLDSA65_PUBLIC_KEY_BYTES)));

  private static final SecretBytes PRIVATE_SEED =
      SecretBytes.copyFrom(
          Hex.decode("01".repeat(MLDSA_SEED_BYTES)), InsecureSecretKeyAccess.get());
  private static final SecretBytes SHORT_PRIVATE_SEED =
      SecretBytes.copyFrom(new byte[MLDSA_SEED_BYTES - 1], InsecureSecretKeyAccess.get());
  private static final SecretBytes LONG_PRIVATE_SEED =
      SecretBytes.copyFrom(new byte[MLDSA_SEED_BYTES + 1], InsecureSecretKeyAccess.get());

  @Test
  @AccessesPartialKey
  public void createNoPrefixAndGetProperties() throws Exception {
    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setParameters(NO_PREFIX_PARAMS)
            .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
            .build();

    MlDsaPrivateKey privateKey = MlDsaPrivateKey.createWithoutVerification(publicKey, PRIVATE_SEED);

    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateSeed()).isEqualTo(PRIVATE_SEED);
    assertThat(privateKey.getParameters()).isEqualTo(NO_PREFIX_PARAMS);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  @AccessesPartialKey
  public void createTinkAndGetProperties() throws Exception {
    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setParameters(TINK_PARAMS)
            .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x66AABBCC)
            .build();

    MlDsaPrivateKey privateKey = MlDsaPrivateKey.createWithoutVerification(publicKey, PRIVATE_SEED);

    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateSeed()).isEqualTo(PRIVATE_SEED);
    assertThat(privateKey.getParameters()).isEqualTo(TINK_PARAMS);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0166AABBCC")));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x66AABBCC);
  }

  @Test
  @AccessesPartialKey
  public void createWithIncorrectSeedSize_fails() throws Exception {
    MlDsaPublicKey publicKey =
        MlDsaPublicKey.builder()
            .setParameters(NO_PREFIX_PARAMS)
            .setSerializedPublicKey(FAKE_PUBLIC_KEY_BYTES)
            .build();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> MlDsaPrivateKey.createWithoutVerification(publicKey, SHORT_PRIVATE_SEED));
    assertThat(e).hasMessageThat().contains("Incorrect private seed size");

    e =
        assertThrows(
            GeneralSecurityException.class,
            () -> MlDsaPrivateKey.createWithoutVerification(publicKey, LONG_PRIVATE_SEED));
    assertThat(e).hasMessageThat().contains("Incorrect private seed size");
  }
}
