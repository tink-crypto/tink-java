// Copyright 2023 Google LLC
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
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HpkeProtoSerialization}. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public final class HpkeProtoSerializationTest {
  private static final class VariantTuple {
    final HpkeParameters.Variant variant;
    final OutputPrefixType outputPrefixType;
    @Nullable final Integer idRequirement;

    VariantTuple(
        HpkeParameters.Variant variant,
        OutputPrefixType outputPrefixType,
        @Nullable Integer idRequirement) {
      this.variant = variant;
      this.outputPrefixType = outputPrefixType;
      this.idRequirement = idRequirement;
    }
  }

  private static final class KemTuple {
    final HpkeParameters.KemId kemId;
    final HpkeKem kemProto;
    final byte[] publicKey;
    final byte[] privateKey;

    KemTuple(HpkeParameters.KemId kemId, HpkeKem kemProto, byte[] publicKey, byte[] privateKey) {
      this.kemId = kemId;
      this.kemProto = kemProto;
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }
  }

  private static final class KdfTuple {
    final HpkeParameters.KdfId kdfId;
    final HpkeKdf kdfProto;

    KdfTuple(HpkeParameters.KdfId kdfId, HpkeKdf kdfProto) {
      this.kdfId = kdfId;
      this.kdfProto = kdfProto;
    }
  }

  private static final class AeadTuple {
    final HpkeParameters.AeadId aeadId;
    final HpkeAead aeadProto;

    AeadTuple(HpkeParameters.AeadId aeadId, HpkeAead aeadProto) {
      this.aeadId = aeadId;
      this.aeadProto = aeadProto;
    }
  }

  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  private static final String XWING_PRIVATE_KEY_HEX =
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
  private static final String XWING_PUBLIC_KEY_HEX =
      "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d"
          + "a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b"
          + "2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534"
          + "01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361"
          + "0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c"
          + "1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06"
          + "3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae"
          + "a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e"
          + "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40"
          + "b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c"
          + "1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362"
          + "543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564"
          + "955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e"
          + "d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af"
          + "829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519"
          + "317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4"
          + "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be"
          + "3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587"
          + "ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584"
          + "fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c"
          + "8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09"
          + "0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95"
          + "2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406"
          + "5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5"
          + "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173"
          + "46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573"
          + "cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369"
          + "8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c"
          + "1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44"
          + "d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96"
          + "9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611"
          + "d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734"
          + "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06"
          + "eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534";

  @DataPoints("variants")
  public static final VariantTuple[] VARIANTS =
      new VariantTuple[] {
        new VariantTuple(
            HpkeParameters.Variant.NO_PREFIX, OutputPrefixType.RAW, /* idRequirement= */ null),
        new VariantTuple(
            HpkeParameters.Variant.TINK, OutputPrefixType.TINK, /* idRequirement= */ 123),
        new VariantTuple(
            HpkeParameters.Variant.CRUNCHY, OutputPrefixType.CRUNCHY, /* idRequirement= */ 456),
      };

  @DataPoints("kems")
  public static final KemTuple[] KEMS =
      new KemTuple[] {
        new KemTuple(
            // Ephemeral key pair from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1.
            HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256,
            HpkeKem.DHKEM_X25519_HKDF_SHA256,
            /* publicKey= */ Hex.decode(
                "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
            /* privateKey= */ Hex.decode(
                "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")),
        new KemTuple(
            // Ephemeral key pair from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1.
            HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256,
            HpkeKem.DHKEM_P256_HKDF_SHA256,
            /* publicKey= */ Hex.decode(
                "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32"
                    + "5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"),
            /* privateKey= */ Hex.decode(
                "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")),
        new KemTuple(
            // Ephemeral key pair from  https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.6.1.
            HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512,
            HpkeKem.DHKEM_P521_HKDF_SHA512,
            /* publicKey= */ Hex.decode(
                "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8"
                    + "900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731"
                    + "ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0"
                    + "692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"),
            /* privateKey= */ Hex.decode(
                "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354"
                    + "15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e37"
                    + "4b")),
        new KemTuple(
            HpkeParameters.KemId.X_WING,
            HpkeKem.X_WING,
            /* publicKey= */ Hex.decode(XWING_PUBLIC_KEY_HEX),
            /* privateKey= */ Hex.decode(XWING_PRIVATE_KEY_HEX)),
      };

  @DataPoints("kdfs")
  public static final KdfTuple[] KDFS =
      new KdfTuple[] {
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA256, HpkeKdf.HKDF_SHA256),
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA384, HpkeKdf.HKDF_SHA384),
        new KdfTuple(HpkeParameters.KdfId.HKDF_SHA512, HpkeKdf.HKDF_SHA512),
      };

  @DataPoints("aeads")
  public static final AeadTuple[] AEADS =
      new AeadTuple[] {
        new AeadTuple(HpkeParameters.AeadId.AES_128_GCM, HpkeAead.AES_128_GCM),
        new AeadTuple(HpkeParameters.AeadId.AES_256_GCM, HpkeAead.AES_256_GCM),
        new AeadTuple(HpkeParameters.AeadId.CHACHA20_POLY1305, HpkeAead.CHACHA20_POLY1305),
      };

  private static final HpkeParams createHpkeProtoParams(HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
    return HpkeParams.newBuilder().setKem(kem).setKdf(kdf).setAead(aead).build();
  }

  private static final com.google.crypto.tink.proto.HpkePublicKey createHpkeProtoPublicKey(
      int version, HpkeParams params, byte[] publicKey) {
    return com.google.crypto.tink.proto.HpkePublicKey.newBuilder()
        .setVersion(version)
        .setParams(params)
        .setPublicKey(ByteString.copyFrom(publicKey))
        .build();
  }

  private static final com.google.crypto.tink.proto.HpkePrivateKey createHpkeProtoPrivateKey(
      int version, com.google.crypto.tink.proto.HpkePublicKey publicKey, byte[] privateKey) {
    return com.google.crypto.tink.proto.HpkePrivateKey.newBuilder()
        .setVersion(version)
        .setPublicKey(publicKey)
        .setPrivateKey(ByteString.copyFrom(privateKey))
        .build();
  }

  @BeforeClass
  public static void setUp() throws Exception {
    HpkeProtoSerialization.register(registry);
  }

  @Test
  public void register_calledTwice_succeedsAndSecondCallHasNoEffect() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .build();

    HpkeParams protoParams =
        createHpkeProtoParams(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);
    HpkeKeyFormat format = HpkeKeyFormat.newBuilder().setParams(protoParams).build();
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            OutputPrefixType.RAW,
            format.toByteString());

    MutableSerializationRegistry registry = new MutableSerializationRegistry();
    assertThat(registry.hasParserForParameters(serialization)).isFalse();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isFalse();

    HpkeProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();

    HpkeProtoSerialization.register(registry);

    assertThat(registry.hasParserForParameters(serialization)).isTrue();
    assertThat(registry.hasSerializerForParameters(parameters, ProtoParametersSerialization.class))
        .isTrue();
  }

  @Theory
  public void serializeParseParameters(
      @FromDataPoints("variants") VariantTuple variantTuple,
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(variantTuple.variant)
            .build();

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    HpkeKeyFormat format = HpkeKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            variantTuple.outputPrefixType,
            format.toByteString());

    ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
    assertEqualWhenValueParsed(HpkeKeyFormat.parser(), serialized, serialization);

    Parameters parsed = registry.parseParameters(serialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParsePublicKey(
      @FromDataPoints("variants") VariantTuple variantTuple,
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(variantTuple.variant)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), variantTuple.idRequirement);

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            variantTuple.outputPrefixType,
            variantTuple.idRequirement);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();

    ProtoKeySerialization serialized = registry.serializeKey(publicKey, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HpkePublicKey.parser(), serialized, serialization);
  }

  @Theory
  public void parsePublicKey_withLegacyOutputPrefix(
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(HpkeParameters.Variant.CRUNCHY)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), /* idRequirement= */ 789);

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 789);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Theory
  public void parsePublicKey_withExtraLeadingZero(
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(HpkeParameters.Variant.TINK)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), /* idRequirement= */ 123);

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    byte[] publicKeyBytes =
        com.google.crypto.tink.subtle.Bytes.concat(new byte[] {0}, kemTuple.publicKey);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, publicKeyBytes);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, /* access= */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Theory
  public void serializeParsePrivateKey(
      @FromDataPoints("variants") VariantTuple variantTuple,
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (TestUtil.isTsan()) {
      // skip test, it's too slow in Tsan.
      return;
    }
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(variantTuple.variant)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), variantTuple.idRequirement);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(kemTuple.privateKey, InsecureSecretKeyAccess.get()));

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);
    com.google.crypto.tink.proto.HpkePrivateKey protoPrivateKey =
        createHpkeProtoPrivateKey(/* version= */ 0, protoPublicKey, kemTuple.privateKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            variantTuple.outputPrefixType,
            /* idRequirement= */ variantTuple.idRequirement);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();

    ProtoKeySerialization serialized =
        registry.serializeKey(privateKey, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.HpkePublicKey.parser(), serialized, serialization);
  }

  @Theory
  public void parsePrivateKey_withLegacyOutputPrefix(
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (TestUtil.isTsan()) {
      // skip test, it's too slow in Tsan.
      return;
    }
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(HpkeParameters.Variant.CRUNCHY)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), /* idRequirement= */ 789);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(kemTuple.privateKey, InsecureSecretKeyAccess.get()));

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);
    com.google.crypto.tink.proto.HpkePrivateKey protoPrivateKey =
        createHpkeProtoPrivateKey(/* version= */ 0, protoPublicKey, kemTuple.privateKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.LEGACY,
            /* idRequirement= */ 789);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }

  @Theory
  public void parsePrivateKey_withExtraLeadingZero(
      @FromDataPoints("kems") KemTuple kemTuple,
      @FromDataPoints("kdfs") KdfTuple kdfTuple,
      @FromDataPoints("aeads") AeadTuple aeadTuple)
      throws Exception {
    if (TestUtil.isTsan()) {
      // skip test, it's too slow in Tsan.
      return;
    }
    if (kemTuple.kemId == HpkeParameters.KemId.X_WING
        && kdfTuple.kdfId != HpkeParameters.KdfId.HKDF_SHA256) {
      return;
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(kemTuple.kemId)
            .setKdfId(kdfTuple.kdfId)
            .setAeadId(aeadTuple.aeadId)
            .setVariant(HpkeParameters.Variant.TINK)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(kemTuple.publicKey), /* idRequirement= */ 123);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(kemTuple.privateKey, InsecureSecretKeyAccess.get()));

    HpkeParams protoParams =
        createHpkeProtoParams(kemTuple.kemProto, kdfTuple.kdfProto, aeadTuple.aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, kemTuple.publicKey);
    byte[] privateKeyBytes =
        com.google.crypto.tink.subtle.Bytes.concat(new byte[] {0}, kemTuple.privateKey);
    com.google.crypto.tink.proto.HpkePrivateKey protoPrivateKey =
        createHpkeProtoPrivateKey(/* version= */ 0, protoPublicKey, privateKeyBytes);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);

    Key parsed = registry.parseKey(serialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }

  @Test
  public void parsePrivateKey_noAccess_throws() throws Exception {
    HpkeParams protoParams =
        createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, KEMS[0].publicKey);
    com.google.crypto.tink.proto.HpkePrivateKey protoPrivateKey =
        createHpkeProtoPrivateKey(/* version= */ 0, protoPublicKey, KEMS[0].privateKey);

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            /* idRequirement= */ 123);
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void serializePrivateKey_noAccess_throws() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(KEMS[0].kemId)
            .setKdfId(KDFS[0].kdfId)
            .setAeadId(AEADS[0].aeadId)
            .setVariant(VARIANTS[0].variant)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(
            parameters, Bytes.copyFrom(KEMS[0].publicKey), VARIANTS[0].idRequirement);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(KEMS[0].privateKey, InsecureSecretKeyAccess.get()));

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, /* access= */ null));
  }

  private static ProtoParametersSerialization[] createInvalidParameters() {
    try {
      return new ProtoParametersSerialization[] {
        // Unknown output prefix.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.UNKNOWN_PREFIX,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto))
                .build()
                .toByteString()),
        // Unknown KEM.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        HpkeKem.KEM_UNKNOWN, KDFS[0].kdfProto, AEADS[0].aeadProto))
                .build()
                .toByteString()),
        // Unknown KDF.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        KEMS[0].kemProto, HpkeKdf.KDF_UNKNOWN, AEADS[0].aeadProto))
                .build()
                .toByteString()),
        // Unknown AEAD.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.TINK,
            HpkeKeyFormat.newBuilder()
                .setParams(
                    createHpkeProtoParams(
                        KEMS[0].kemProto, KDFS[0].kdfProto, HpkeAead.AEAD_UNKNOWN))
                .build()
                .toByteString()),
        // Proto messages start with a VarInt, which always ends with a byte with most
        // significant bit unset. 0x80 is hence invalid.
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType.RAW,
            ByteString.copyFrom(new byte[] {(byte) 0x80})),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidParametersSerializations")
  public static final ProtoParametersSerialization[] invalidParametersSerializations =
      createInvalidParameters();

  @Theory
  public void parseInvalidParameters_fails(
      @FromDataPoints("invalidParametersSerializations")
          ProtoParametersSerialization serializedParameters)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseParameters(serializedParameters));
  }

  private static ProtoKeySerialization[] createInvalidPublicKeySerializations() {
    try {
      return new ProtoKeySerialization[] {
        // Bad Version Number (1)
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            createHpkeProtoPublicKey(
                    /* version= */ 1,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
        // Unknown prefix
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            createHpkeProtoPublicKey(
                    /* version= */ 0,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.UNKNOWN_PREFIX,
            123),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
        // Wrong Type URL
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            createHpkeProtoPublicKey(
                    /* version= */ 0,
                    createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto),
                    KEMS[0].publicKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            123),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final ProtoKeySerialization[] INVALID_PUBLIC_KEY_SERIALIZATIONS =
      createInvalidPublicKeySerializations();

  @Theory
  public void parseInvalidPublicKeys_throws(
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization) {
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  private static ProtoKeySerialization[] createInvalidPrivateKeySerializations() {
    try {
      HpkeParams protoParams =
          createHpkeProtoParams(KEMS[0].kemProto, KDFS[0].kdfProto, AEADS[0].aeadProto);
      com.google.crypto.tink.proto.HpkePublicKey validProtoPublicKey =
          createHpkeProtoPublicKey(/* version= */ 0, protoParams, KEMS[0].publicKey);

      return new ProtoKeySerialization[] {
        // Bad private key value.
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            createHpkeProtoPrivateKey(/* version= */ 0, validProtoPublicKey, Random.randBytes(4))
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
        // Bad version number (1).
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            createHpkeProtoPrivateKey(/* version= */ 1, validProtoPublicKey, KEMS[0].privateKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
        // Bad public key version number (1).
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            createHpkeProtoPrivateKey(
                    /* version= */ 0,
                    createHpkeProtoPublicKey(/* version= */ 1, protoParams, KEMS[0].publicKey),
                    KEMS[0].privateKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
        // Unknown prefix.
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            createHpkeProtoPrivateKey(/* version= */ 0, validProtoPublicKey, KEMS[0].privateKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.UNKNOWN_PREFIX,
            123),
        // Invalid public key.
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            createHpkeProtoPrivateKey(
                    /* version= */ 0,
                    createHpkeProtoPublicKey(/* version= */ 0, protoParams, Random.randBytes(4)),
                    KEMS[0].privateKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
        // Invalid proto encoding
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            // Proto messages start with a VarInt, which always ends with a byte with most
            // significant bit unset. 0x80 is hence invalid.
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
        // Wrong Type URL
        ProtoKeySerialization.create(
            "WrongTypeUrl",
            createHpkeProtoPrivateKey(/* version= */ 0, validProtoPublicKey, KEMS[0].privateKey)
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.TINK,
            123),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @DataPoints("invalidPrivateKeySerializations")
  public static final ProtoKeySerialization[] INVALID_PRIVATE_KEY_SERIALIZATIONS =
      createInvalidPrivateKeySerializations();

  @Theory
  public void parseInvalidPrivateKeys_throws(
      @FromDataPoints("invalidPrivateKeySerializations") ProtoKeySerialization serialization) {
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parseParameters_xwingWithUnsupportedKdf_throws() throws Exception {
    HpkeParams protoParams =
        createHpkeProtoParams(HpkeKem.X_WING, HpkeKdf.HKDF_SHA384, HpkeAead.AES_128_GCM);
    HpkeKeyFormat format = HpkeKeyFormat.newBuilder().setParams(protoParams).build();

    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            OutputPrefixType.RAW,
            format.toByteString());

    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @Test
  public void parsePublicKey_xwingWithUnsupportedKdf_throws() throws Exception {
    HpkeParams protoParams =
        createHpkeProtoParams(HpkeKem.X_WING, HpkeKdf.HKDF_SHA384, HpkeAead.AES_128_GCM);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, Hex.decode(XWING_PUBLIC_KEY_HEX));

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePublicKey",
            protoPublicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @Test
  public void parsePrivateKey_xwingWithUnsupportedKdf_throws() throws Exception {
    HpkeParams protoParams =
        createHpkeProtoParams(HpkeKem.X_WING, HpkeKdf.HKDF_SHA384, HpkeAead.AES_128_GCM);
    com.google.crypto.tink.proto.HpkePublicKey protoPublicKey =
        createHpkeProtoPublicKey(/* version= */ 0, protoParams, Hex.decode(XWING_PUBLIC_KEY_HEX));
    com.google.crypto.tink.proto.HpkePrivateKey protoPrivateKey =
        createHpkeProtoPrivateKey(
            /* version= */ 0, protoPublicKey, Hex.decode(XWING_PRIVATE_KEY_HEX));

    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
            protoPrivateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
