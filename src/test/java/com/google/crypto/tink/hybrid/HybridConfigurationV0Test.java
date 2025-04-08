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
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
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
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
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

  private static final String AES_GCM_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";

  @Test
  public void config_handlesEciesAeadHkdfLegacyKeyForHybridEncrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.EciesHkdfKemParams kemParams =
        com.google.crypto.tink.proto.EciesHkdfKemParams.newBuilder()
            .setCurveType(com.google.crypto.tink.proto.EllipticCurveType.NIST_P256)
            .setHkdfHashType(com.google.crypto.tink.proto.HashType.SHA256)
            .build();
    com.google.crypto.tink.proto.EciesAeadDemParams demParams =
        com.google.crypto.tink.proto.EciesAeadDemParams.newBuilder()
            .setAeadDem(
                com.google.crypto.tink.proto.KeyTemplate.newBuilder()
                    .setTypeUrl(AES_GCM_KEY_TYPE_URL)
                    .setOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType.TINK)
                    .setValue(
                        KeyTemplate.newBuilder()
                            .setTypeUrl(AES_GCM_KEY_TYPE_URL)
                            .setValue(
                                com.google.crypto.tink.proto.AesGcmKeyFormat.newBuilder()
                                    .setKeySize(32)
                                    .build()
                                    .toByteString())
                            .setOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType.RAW)
                            .build()
                            .getValue())
                    .build())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    com.google.crypto.tink.proto.EciesAeadHkdfParams.newBuilder()
                        .setKemParams(kemParams)
                        .setDemParams(demParams)
                        .setEcPointFormat(com.google.crypto.tink.proto.EcPointFormat.COMPRESSED)
                        .build())
                .setX(
                    ByteString.copyFrom(
                        Hex.decode(
                            "0060FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")))
                .setY(
                    ByteString.copyFrom(
                        Hex.decode(
                            "007903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    EciesProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridEncrypt.class)).isNotNull();
  }

  @Test
  public void config_handlesEciesAeadHkdfLegacyKeyForHybridDecrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.EciesHkdfKemParams kemParams =
        com.google.crypto.tink.proto.EciesHkdfKemParams.newBuilder()
            .setCurveType(com.google.crypto.tink.proto.EllipticCurveType.NIST_P256)
            .setHkdfHashType(com.google.crypto.tink.proto.HashType.SHA256)
            .build();
    com.google.crypto.tink.proto.EciesAeadDemParams demParams =
        com.google.crypto.tink.proto.EciesAeadDemParams.newBuilder()
            .setAeadDem(
                com.google.crypto.tink.proto.KeyTemplate.newBuilder()
                    .setTypeUrl(AES_GCM_KEY_TYPE_URL)
                    .setOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType.TINK)
                    .setValue(
                        KeyTemplate.newBuilder()
                            .setTypeUrl(AES_GCM_KEY_TYPE_URL)
                            .setValue(
                                com.google.crypto.tink.proto.AesGcmKeyFormat.newBuilder()
                                    .setKeySize(32)
                                    .build()
                                    .toByteString())
                            .setOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType.RAW)
                            .build()
                            .getValue())
                    .build())
            .build();
    com.google.crypto.tink.proto.EciesAeadHkdfPublicKey protoPublicKey =
        com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                com.google.crypto.tink.proto.EciesAeadHkdfParams.newBuilder()
                    .setKemParams(kemParams)
                    .setDemParams(demParams)
                    .setEcPointFormat(com.google.crypto.tink.proto.EcPointFormat.COMPRESSED)
                    .build())
            .setX(
                ByteString.copyFrom(
                    Hex.decode(
                        "00" + "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")))
            .setY(
                ByteString.copyFrom(
                    Hex.decode(
                        "00" + "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(protoPublicKey)
                .setKeyValue(
                    ByteString.copyFrom(
                        Hex.decode(
                            "00C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    EciesProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class)).isNotNull();
  }

  @Test
  public void config_handlesHpkeLegacyKeyForHybridEncrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
                .setVersion(0)
                .setParams(
                    com.google.crypto.tink.proto.HpkeParams.newBuilder()
                        .setKem(com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256)
                        .setKdf(com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256)
                        .setAead(com.google.crypto.tink.proto.HpkeAead.AES_128_GCM)
                        .build())
                .setPublicKey(
                    ByteString.copyFrom(
                        Hex.decode(
                            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    HpkeProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridEncrypt.class)).isNotNull();
  }

  @Test
  public void config_handlesHpkeLegacyKeyForHybridDecrypt() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    com.google.crypto.tink.proto.HpkePublicKey publicKey =
        com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(
                com.google.crypto.tink.proto.HpkeParams.newBuilder()
                    .setKem(com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256)
                    .setKdf(com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256)
                    .setAead(com.google.crypto.tink.proto.HpkeAead.AES_128_GCM)
                    .build())
            .setPublicKey(
                ByteString.copyFrom(
                    Hex.decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")))
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            com.google.crypto.tink.proto.HpkePrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(publicKey)
                .setPrivateKey(
                    ByteString.copyFrom(
                        Hex.decode(
                            "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            com.google.crypto.tink.proto.OutputPrefixType.RAW,
            null);
    LegacyProtoKey key = new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    HpkeProtoSerialization.register();

    assertThat(keysetHandle.getPrimitive(HybridConfigurationV0.get(), HybridDecrypt.class)).isNotNull();
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
