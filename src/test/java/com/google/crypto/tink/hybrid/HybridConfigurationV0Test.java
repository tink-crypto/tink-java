// Copyright 2024 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.internal.AesCtrHmacAeadProtoSerialization;
import com.google.crypto.tink.aead.internal.AesGcmProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.hybrid.EciesParameters.CurveType;
import com.google.crypto.tink.hybrid.EciesParameters.PointFormat;
import com.google.crypto.tink.hybrid.HpkeParameters.AeadId;
import com.google.crypto.tink.hybrid.HpkeParameters.KdfId;
import com.google.crypto.tink.hybrid.HpkeParameters.KemId;
import com.google.crypto.tink.hybrid.internal.EciesProtoSerialization;
import com.google.crypto.tink.hybrid.internal.testing.EciesAeadHkdfTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class HybridConfigurationV0Test {
  @BeforeClass
  public static void setUp() throws Exception {
    EciesProtoSerialization.register();
    AesGcmProtoSerialization.register();
    AesCtrHmacAeadProtoSerialization.register();
    AesSivProtoSerialization.register();

    HpkeProtoSerialization.register();
  }

  @Test
  public void config_throwsIfInFipsMode() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());

    assertThrows(GeneralSecurityException.class, HybridConfigurationV0::get);
  }

  @Test
  public void config_containsEciesAeadHkdfForHybridEncrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesGcmParameters demParameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(CurveType.NIST_P384)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(PointFormat.UNCOMPRESSED)
            .setDemParameters(demParameters)
            .setVariant(EciesParameters.Variant.TINK)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P384);
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters, ((ECPublicKey) keyPair.getPublic()).getW(), /* idRequirement= */ 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(publicKey).makePrimary()).build();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridEncrypt.class))
        .isNotNull();
  }

  @Test
  public void config_containsEciesAeadHkdfForHybridDecrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesGcmParameters demParameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(CurveType.NIST_P384)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(PointFormat.UNCOMPRESSED)
            .setDemParameters(demParameters)
            .setVariant(EciesParameters.Variant.TINK)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P384);
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters, ((ECPublicKey) keyPair.getPublic()).getW(), /* idRequirement= */ 42);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(
                ((ECPrivateKey) keyPair.getPrivate()).getS(), InsecureSecretKeyAccess.get()));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(privateKey).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class))
        .isNotNull();
  }

  @Test
  public void config_containsHpkeForHybridEncrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(KdfId.HKDF_SHA384)
            .setAeadId(AeadId.AES_256_GCM)
            .setVariant(HpkeParameters.Variant.TINK)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P384);
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                EllipticCurves.CurveType.NIST_P384,
                PointFormatType.UNCOMPRESSED,
                ((ECPublicKey) keyPair.getPublic()).getW()));
    HpkePublicKey publicKey = HpkePublicKey.create(parameters, publicKeyBytes, 42);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(publicKey).makePrimary()).build();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridEncrypt.class))
        .isNotNull();
  }

  @Test
  public void config_containsHpkeForHybridDecrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(KdfId.HKDF_SHA384)
            .setAeadId(AeadId.AES_256_GCM)
            .setVariant(HpkeParameters.Variant.TINK)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P384);
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                EllipticCurves.CurveType.NIST_P384,
                PointFormatType.UNCOMPRESSED,
                ((ECPublicKey) keyPair.getPublic()).getW()));
    HpkePublicKey publicKey = HpkePublicKey.create(parameters, publicKeyBytes, 42);
    byte[] privateKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            ((ECPrivateKey) keyPair.getPrivate()).getS(), 48);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(privateKey).makePrimary())
            .build();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class))
        .isNotNull();
  }

  @Theory
  public void decryptCiphertextWorks(@FromDataPoints("hybridTests") HybridTestVector v)
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    HybridDecrypt hybridDecrypt =
        handle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class);
    byte[] plaintext = hybridDecrypt.decrypt(v.getCiphertext(), v.getContextInfo());

    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }

  @Theory
  public void decryptWrongContextInfoThrows(@FromDataPoints("hybridTests") HybridTestVector v)
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    byte[] contextInfo = v.getContextInfo();
    if (contextInfo.length > 0) {
      contextInfo[0] ^= 1;
    } else {
      contextInfo = new byte[] {1};
    }
    // local variables referenced from a lambda expression must be final or effectively final
    final byte[] contextInfoCopy = Arrays.copyOf(contextInfo, contextInfo.length);

    HybridDecrypt hybridDecrypt =
        handle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class);

    assertThrows(
        GeneralSecurityException.class,
        () -> hybridDecrypt.decrypt(v.getCiphertext(), contextInfoCopy));
  }

  @Theory
  public void encryptThenDecryptMessageWorks(@FromDataPoints("hybridTests") HybridTestVector v)
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    HybridDecrypt hybridDecrypt =
        handle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class);
    HybridEncrypt hybridEncrypt =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV0.get(), HybridEncrypt.class);
    byte[] ciphertext = hybridEncrypt.encrypt(v.getPlaintext(), v.getContextInfo());
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, v.getContextInfo());

    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }

  @DataPoints("hybridTests")
  public static final HybridTestVector[] hybridTestVectors =
      Stream.concat(
              Arrays.stream(HpkeTestUtil.createHpkeTestVectors()),
              Arrays.stream(EciesAeadHkdfTestUtil.createEciesTestVectors()))
          .toArray(HybridTestVector[]::new);
}
