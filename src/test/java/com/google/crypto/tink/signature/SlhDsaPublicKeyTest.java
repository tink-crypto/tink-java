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
import com.google.crypto.tink.signature.SlhDsaParameters.Variant;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
@AccessesPartialKey
public class SlhDsaPublicKeyTest {
  // Test case from tink/go/internal/signature/slhdsa/slhdsa_kat_vectors_test.go
  private static final String SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX =
      "66e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
  private static final Bytes SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode(SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX));

  @Test
  public void buildSha2128S_tinkVariant_succeeds() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();

    assertThat(publicKey.getParameters()).isEqualTo(parameters);
    assertThat(publicKey.getSerializedPublicKey()).isEqualTo(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES);
    assertThat(publicKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(Hex.decode("0112345678")));
    assertThat(publicKey.getIdRequirementOrNull()).isEqualTo(0x12345678);
  }

  @Test
  public void buildSha2128S_noPrefixVariant_succeeds() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();

    assertThat(publicKey.getParameters()).isEqualTo(parameters);
    assertThat(publicKey.getSerializedPublicKey()).isEqualTo(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES);
    assertThat(publicKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(publicKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void build_tinkVariant_noIdRequirement_throws() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SlhDsaPublicKey.builder()
                .setParameters(parameters)
                .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
                .build());
  }

  @Test
  public void build_noPrefixVariant_withIdRequirement_throws() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SlhDsaPublicKey.builder()
                .setParameters(parameters)
                .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
                .setIdRequirement(0x12345678)
                .build());
  }

  @Test
  public void build_noParameters_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SlhDsaPublicKey.builder()
                .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
                .build());
  }

  @Test
  public void build_noPublicKeyBytes_throws() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    assertThrows(
        GeneralSecurityException.class,
        () -> SlhDsaPublicKey.builder().setParameters(parameters).build());
  }

  @Test
  public void build_wrongPublicKeyBytesSize_throws() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SlhDsaPublicKey.builder()
                .setParameters(parameters)
                .setSerializedPublicKey(
                    Bytes.copyFrom(Hex.decode(SLH_DSA_SHA2_128S_PUBLIC_KEY_HEX + "00")))
                .build());
  }

  @Test
  public void testEqualsKey() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();
    SlhDsaPublicKey otherPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();

    assertThat(publicKey.equalsKey(otherPublicKey)).isTrue();
  }

  @Test
  public void testNotEqualsKey_differentParameters() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();
    SlhDsaParameters otherParameters =
        SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey otherPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(otherParameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();

    assertThat(publicKey.equalsKey(otherPublicKey)).isFalse();
  }

  @Test
  public void testNotEqualsKey_differentIdRequirement() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.TINK);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x12345678)
            .build();
    SlhDsaPublicKey otherPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .setIdRequirement(0x87654321)
            .build();

    assertThat(publicKey.equalsKey(otherPublicKey)).isFalse();
  }

  @Test
  public void testNotEqualsKey_differentKeyBytes() throws Exception {
    SlhDsaParameters parameters = SlhDsaParameters.createSlhDsaWithSha2And128S(Variant.NO_PREFIX);
    SlhDsaPublicKey publicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(SLH_DSA_SHA2_128S_PUBLIC_KEY_BYTES)
            .build();
    String otherPublicKeyHex =
        "76e94bff8074e57fb66e9627596140df21f975f9c51286d8198ba57ddd099321";
    SlhDsaPublicKey otherPublicKey =
        SlhDsaPublicKey.builder()
            .setParameters(parameters)
            .setSerializedPublicKey(Bytes.copyFrom(Hex.decode(otherPublicKeyHex)))
            .build();

    assertThat(publicKey.equalsKey(otherPublicKey)).isFalse();
  }
}
