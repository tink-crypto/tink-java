// Copyright 2026 Google LLC
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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.signature.internal.testing.MlDsaMuTestUtil;
import com.google.crypto.tink.signature.internal.testing.MlDsaMuTestVector;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class MlDsaPrehashConscryptTest {
  private static final byte[] testData = "this is some data to be prehashed".getBytes(UTF_8);

  private static final int KEY_ID = 0x01020304;
  private static final String PREHASH_PREFIX_HEX = "ff01020304";

  @DataPoints("testVectors")
  public static final MlDsaMuTestVector[] testVectors =
      MlDsaMuTestUtil.createMlDsaMuTestVectors().toArray(new MlDsaMuTestVector[0]);

  /** Returns the public key of {@code testVector}, with the ID requirement {@link #KEY_ID}. */
  private static MlDsaPublicKey tinkPublicKey(MlDsaMuTestVector testVector)
      throws GeneralSecurityException {
    return MlDsaPublicKey.builder()
        .setParameters(MlDsaParameters.create(testVector.getInstance(), Variant.TINK))
        .setSerializedPublicKey(
            com.google.crypto.tink.util.Bytes.copyFrom(testVector.getPublicKeyBytes()))
        .setIdRequirement(KEY_ID)
        .build();
  }

  /** Returns the public key of {@code testVector}, without an ID requirement. */
  private static MlDsaPublicKey noPrefixPublicKey(MlDsaMuTestVector testVector)
      throws GeneralSecurityException {
    return MlDsaPublicKey.builder()
        .setParameters(MlDsaParameters.create(testVector.getInstance(), Variant.NO_PREFIX))
        .setSerializedPublicKey(
            com.google.crypto.tink.util.Bytes.copyFrom(testVector.getPublicKeyBytes()))
        .build();
  }

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }
  }

  @Theory
  public void compute_matchesTestVector(@FromDataPoints("testVectors") MlDsaMuTestVector testVector)
      throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    // An early return is used instead of an assumption, because the Theories runner fails when
    // the assumption is violated for all data points.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    Prehash prehash = MlDsaPrehashConscrypt.create(tinkPublicKey(testVector));

    // The prehash value is the prehash prefix of the key, followed by mu.
    assertThat(prehash.compute(testVector.getMessage()))
        .isEqualTo(Bytes.concat(Hex.decode(PREHASH_PREFIX_HEX), testVector.getMu()));
  }

  @Theory
  public void compute_isDeterministicAndDependsOnData(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    Prehash prehash = MlDsaPrehashConscrypt.create(tinkPublicKey(testVector));
    byte[] prehashValue = prehash.compute(testData);

    assertThat(prehashValue).hasLength(5 + 64);
    assertThat(Hex.encode(Arrays.copyOf(prehashValue, 5))).isEqualTo(PREHASH_PREFIX_HEX);
    assertThat(prehash.compute(testData)).isEqualTo(prehashValue);
    assertThat(prehash.compute(new byte[0])).isNotEqualTo(prehashValue);
    assertThat(prehash.compute(new byte[0])).hasLength(5 + 64);
  }

  @Theory
  public void compute_dependsOnPublicKey(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    MlDsaPublicKey publicKey = tinkPublicKey(testVector);
    byte[] otherPublicKeyBytes = testVector.getPublicKeyBytes();
    otherPublicKeyBytes[otherPublicKeyBytes.length - 1] ^= 0x01;
    MlDsaPublicKey otherPublicKey =
        MlDsaPublicKey.builder()
            .setParameters(publicKey.getParameters())
            .setSerializedPublicKey(com.google.crypto.tink.util.Bytes.copyFrom(otherPublicKeyBytes))
            .setIdRequirement(KEY_ID)
            .build();

    byte[] prehashValue = MlDsaPrehashConscrypt.create(publicKey).compute(testData);
    byte[] otherPrehashValue = MlDsaPrehashConscrypt.create(otherPublicKey).compute(testData);

    // Same prefix, since the keys have the same ID, but a different mu.
    assertThat(Arrays.copyOf(otherPrehashValue, 5)).isEqualTo(Arrays.copyOf(prehashValue, 5));
    assertThat(otherPrehashValue).isNotEqualTo(prehashValue);
  }

  @Theory
  public void create_keyWithoutIdRequirement_throws(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    MlDsaPublicKey publicKey = noPrefixPublicKey(testVector);

    assertThrows(GeneralSecurityException.class, () -> MlDsaPrehashConscrypt.create(publicKey));
  }

  @Theory
  public void createWithProvider_works(@FromDataPoints("testVectors") MlDsaMuTestVector testVector)
      throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    Provider provider = ConscryptUtil.providerOrNull();
    assertThat(provider).isNotNull();

    Prehash prehash = MlDsaPrehashConscrypt.createWithProvider(tinkPublicKey(testVector), provider);

    assertThat(prehash.compute(testVector.getMessage()))
        .isEqualTo(Bytes.concat(Hex.decode(PREHASH_PREFIX_HEX), testVector.getMu()));
  }

  @Theory
  public void createWithProvider_providerIsNull_throws(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    Provider nullProvider = null;
    MlDsaPublicKey publicKey = tinkPublicKey(testVector);

    assertThrows(
        NullPointerException.class,
        () -> MlDsaPrehashConscrypt.createWithProvider(publicKey, nullProvider));
  }

  @Theory
  public void createWithProvider_worksWithoutGlobalConscryptProvider(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    // TODO(b/458349867): remove this check once ML-DSA is available on Android and OSS Conscrypt.
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return;
    }
    Provider conscryptProvider = Conscrypt.newProvider();
    Security.removeProvider(conscryptProvider.getName());
    try {
      Prehash prehash =
          MlDsaPrehashConscrypt.createWithProvider(tinkPublicKey(testVector), conscryptProvider);

      assertThat(prehash.compute(testVector.getMessage()))
          .isEqualTo(Bytes.concat(Hex.decode(PREHASH_PREFIX_HEX), testVector.getMu()));
    } finally {
      Security.addProvider(conscryptProvider);
    }
  }

  @Theory
  public void createWithProvider_nonConscryptProvider_throws(
      @FromDataPoints("testVectors") MlDsaMuTestVector testVector) throws Exception {
    MlDsaPublicKey publicKey = tinkPublicKey(testVector);
    Provider nonConscryptProvider = new Provider("NotConscrypt", "1.0", "test provider") {};

    assertThrows(
        GeneralSecurityException.class,
        () -> MlDsaPrehashConscrypt.createWithProvider(publicKey, nonConscryptProvider));
  }

  @Test
  public void fips_primitiveCreationFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThat(MlDsaPrehashConscrypt.isSupported()).isFalse();
    for (MlDsaMuTestVector testVector : testVectors) {
      MlDsaPublicKey publicKey = tinkPublicKey(testVector);
      assertThrows(GeneralSecurityException.class, () -> MlDsaPrehashConscrypt.create(publicKey));
    }
  }

  @Test
  public void noConscryptSupport_primitiveCreationFails() throws Exception {
    Assume.assumeFalse(MlDsaPrehashConscrypt.isSupported());

    for (MlDsaMuTestVector testVector : testVectors) {
      MlDsaPublicKey publicKey = tinkPublicKey(testVector);
      assertThrows(GeneralSecurityException.class, () -> MlDsaPrehashConscrypt.create(publicKey));
    }
  }
}
