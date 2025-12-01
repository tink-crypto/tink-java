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
import com.google.crypto.tink.signature.SlhDsaParameters.Variant;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@AccessesPartialKey
public class SlhDsaPrivateKeyTest {
  // Test case from tink/go/internal/signature/slhdsa/slhdsa_kat_vectors_test.go
  private static final String SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX =
      "66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final Bytes SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode(SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX));

  private static final String SLH_DSA_SHA2_128S_PRIVATE_KEY_HEX =
      "5b13979e405179ea3c7b250ddf5637bc081990d028080b35f09b1db79bd9083d66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final SecretBytes SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES =
      SecretBytes.copyFrom(
          Hex.decode(SLH_DSA_SHA2_128S_PRIVATE_KEY_HEX), InsecureSecretKeyAccess.get());

  @Test
  public void buildSlhDsaSha2128S_tinkVariant_succeeds() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();

    SlhDsaPrivateKey privateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateKeyBytes())
        .isEqualTo(SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0112345678")));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x12345678);
  }

  @Test
  public void buildSlhDsaSha2128S_noPrefixVariant_succeeds() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();

    SlhDsaPrivateKey privateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    assertThat(privateKey.getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getPrivateKeyBytes())
        .isEqualTo(SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildWithWrongPrivateKeySize_fails() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();

    SecretBytes wrongPrivateKeyBytes =
        SecretBytes.copyFrom(
            Hex.decode("5b13979e405179ea3c7b250ddf5637bc081990d028080b35f09b1db79bd908"),
            InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () -> SlhDsaPrivateKey.createWithoutVerification(publicKey, wrongPrivateKeyBytes));
  }

  @Test
  public void privateKeyEquals() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();
    SlhDsaPrivateKey privateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);
    SlhDsaPrivateKey otherPrivateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    assertThat(privateKey.equalsKey(otherPrivateKey)).isTrue();
  }

  @Test
  public void privateKeyNotEquals_differentPublicKey() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();
    SlhDsaPrivateKey privateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    SlhDsaParameters otherParameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey otherPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(otherParameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();
    SlhDsaPrivateKey otherPrivateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            otherPublicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    assertThat(privateKey.equalsKey(otherPrivateKey)).isFalse();
  }

  @Test
  public void privateKeyNotEquals_differentPrivateKeyBytes() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();
    SlhDsaPrivateKey privateKey =
        SlhDsaPrivateKey.createWithoutVerification(
            publicKey, SLH_DSA_SHA2_128S_PRIVATE_KEY_SECRET_BYTES);

    String otherPrivateKeyHex =
        "6b13979e405179ea3c7b250ddf5637bc081990d028080b35f09b1db79bd9083d66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
    SecretBytes otherPrivateKeyBytes =
        SecretBytes.copyFrom(Hex.decode(otherPrivateKeyHex), InsecureSecretKeyAccess.get());
    SlhDsaPrivateKey otherPrivateKey =
        SlhDsaPrivateKey.createWithoutVerification(publicKey, otherPrivateKeyBytes);

    assertThat(privateKey.equalsKey(otherPrivateKey)).isFalse();
  }
}
