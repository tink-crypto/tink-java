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
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.aead.internal.AesGcmProtoSerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.proto.CompositeMlDsaClassicalAlgorithm;
import com.google.crypto.tink.proto.CompositeMlDsaKeyFormat;
import com.google.crypto.tink.proto.CompositeMlDsaParams;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.Variant;
import com.google.crypto.tink.signature.CompositeMlDsaPrivateKey;
import com.google.crypto.tink.signature.CompositeMlDsaPublicKey;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for CompositeMlDsaProtoSerialization. */
@RunWith(Theories.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class CompositeMlDsaProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey";
  private static final String ML_DSA_65_PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  private static final String ML_DSA_65_PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";
  private static final String ED25519_PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  private static final String ED25519_PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";

  private static final com.google.crypto.tink.proto.CompositeMlDsaParams.Builder
      compositeMlDsa65Ed25519ParamsBuilder =
          CompositeMlDsaParams.newBuilder()
              .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
              .setClassicalAlgorithm(CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519);

  private static final String PUBLIC_KEY_ML_DSA_65_HEX =
      "51a09ab1023acc98a397a0a019307fd3a3f43a8d3064197725e7fdc06d262dc92895483e"
          + "81254addd9e72bfedd5e3d17497e079be5bd5d162838e3eabd6bc10c3e274d8bfaeaac99"
          + "d1206fc20ecdb84d8ef3b3dfca8557a2218325b0de00733f7dbce7f255e50959e845d72b"
          + "1ffe277c87de88bc75e239352f513830e74e3999428358c884d5578aee9be53bc54ae891"
          + "91c758f58f43a0d03e8211270288022e01538159b071c4328882a9726c17263079ec1d98"
          + "19d97fd39ba770ccf283cda1e2ff20f095e74479556483f5e9af8d98f206d0825c964f21"
          + "5e18ccfcee6a1419b31c8d8e26e7b54fb6a87b488b8cb54e91177a431268e73f2417a3dc"
          + "81140fca7c69c9c20b93faba91fc42e67fd017682f5589c64cd0c3d5b5a503d7fcfbe347"
          + "46932cb0ccde62fdb42a6d3c8f3d493eed6625c25755b8b970b8dc6deb159930be575f23"
          + "7fadfe3fd1af05b6bd4297979fc3af0d4e0503030c21e78b141aa24029cfd9807893a82f"
          + "b33b8a91d6a8a94c67c7d380ef6a573c73be6ed605498440e23e2151ed87819b069992f2"
          + "f7d2b24073efebdf51d5a1e67e16f837a12b3139d4e4f7a7d5c9214da83731e08a906118"
          + "ee63e822da91f9ef9570538a78aa95649e5f829dc3095fbbaf31607b07d25ef7665adbde"
          + "4fd4ac1ddb70cbd69e80564c7a72c6e58a1a429e4aeed2bdf7177d0e057f2ccaa2acf8ae"
          + "ceee7fc20e609e0d6760abdbf4b5fea64e67b5620df677266b3cec53b8470e92fbbe02b1"
          + "969b8ffa07d2191b6402102c18ed75b441c446a36ccb7be6b39693770ecf32067208ee06"
          + "24ca7f6f5e702cdacaec9590a70c9a251ec977fa1fa9f8e5fe806de8acbfeb57310a721e"
          + "c31aa1e903bdfb220c1e7021f89c47c0698e9edf8c6c6ff20df554855058baa83f9631bd"
          + "31105ccbd953be038f6d23280bdd0e8506ba37da4463b2dc4a66015723ee4dfc44a9abab"
          + "0f19f0597e7a76848e65aa5abd00d65f96704f5e3f8a1ccc112f23d2821d0244d72eb952"
          + "d39ce0968c694e6e1640e76d20847fc5e2fd94574e7fa0047b4e60088d6f511224b92f56"
          + "a30103db1771f2dd36d9d30cf937f80a04dbe3234dd3c716ccca8cd141f92ace71fa5290"
          + "0e7c73874ce2e891b35081e7a4cabbdd61b3944931b5ec67744648d5a89daba3bcff0beb"
          + "e759817dc009e5780fbd45553b5d5e562fd94a41e00cf0c4578468871ddec77a9f7cb301"
          + "91dad5760974983e31488a24a412a44e885a8386fc16831b25c17edfb140ffc0112bd9ae"
          + "decd3976655fafc681210efe44425341fd3ee458309ae350c0b96dbc50914e4712687a9d"
          + "ffcfb435ab0597d5607934d4ea711ebc8feda87d8c14bebef69c7eaaa8c7742d0cdb295b"
          + "d25795b7737b5d30503ef5e3dfc37973aebfc1935cc8d195c9f374cdba78d0fe871ad6cc"
          + "fb9001ad35f9917ace444d6d448ab2b7357d61d78741d6e43b77cf6b8674d927af1aa426"
          + "f668d0cf0ba0fd889362eb652f73b1d1be0dc6f86f0f4d4207473da9263829a3197f894e"
          + "68130f1e02b2f8cbfcf24af5bb78be40e0f21220c93b53ba4a373429a8be89cfa03a24ac"
          + "9cedacc0c378adf9e1f0107908254f7bb61afc81ca53f2d7c76972b8dea425f04bca595d"
          + "a60ddffa49d00f70eeb8af13e35887bdc760beeda66baecf93a465375774ac50b2462d73"
          + "2e6736c3de8733760fb583514ea32b74e097c8052fa089490b47170d2ece6ba39aca9cef"
          + "939e582ab792679e82e3b9d8593193b2aa8ff11d4806da28bda27429a5c5a9d264986eec"
          + "1cffafac707070a648096beff100c5890a7280eb71890f225c44025f17a51bc72b329f4c"
          + "b7f1cae3b2561fc525e340cb8b86b545de4335aa45d9468e4b6e9c5b459eb0abc1c79523"
          + "29e7b19e5ad83722d2dec2233b308b55a3c8af2dfd3f21accb28112dd05297cc934e963c"
          + "c08fad897c32e223742052ac50f993b8de5d7966a32ab5a2107fbe0da9c09ebbd9c66b86"
          + "e4286977976dd7539d34f7960bc94d7ccff98825dabdf51af3aed87f8653e71a5f19a635"
          + "c54ef00d8e097d91e686d144fd6e9840d72c6c87d4acf497696f3ac91a94ddc6f88bd11d"
          + "8c6a1bc209118ccabf565b82a3b6226440fd3b2eb9825128428c142ff7955d2c9c902a2c"
          + "936db386b1c390440e32d1939256804b5c032368751a11bfa8be1742c4c44e32edc6ab2b"
          + "00c519831c8e8ebcd0de15d0d752a3dc4b1845d5bfcf7b958aefa415241c05edcbb07a0c"
          + "7dffdb7780576e4dd5ef564437a880567f07f6d0606aab2e8e71de453fdeb9469fa3fa79"
          + "bc32218c01f6f7394969706b950afdd7afbcea0e0266ea4d5da76a96cd9970b014a8f35b"
          + "fb30b255c938bc72c57cfe177932243a92b7e013847bafee10bc262dd77ffdd0d979c57c"
          + "31a00a3cbcbff215212cdf407d45c9290ca894fa7f8b0792a8103d045ba9007e23823fe3"
          + "efe264664b644fd92d7227d085494eb29acd1a619d1c7a6ee0ec0e083459d1986be6c426"
          + "c57004298701825768b95477a9c279be47869b11d1568423c39e789862d15d3014239ec6"
          + "15a1aa39e92e6a1c062fee26582675576b88a1fe4bed76e15d9f5fe4cf36b549220bb32d"
          + "dc64400c6e0d99e39e47d9feca3f39d418c88e48b950b7fab7a36c7301e42c97e49d0a99"
          + "812eaa10c3bb60e2e15e987d4009cf9468e28de331ba4d66103ef9b644d89a72300cc1e4"
          + "012617a8bd4a4f958451da83bb8a64b2f09a8d5ac898693db9c36a92ab0530042d41111d"
          + "5c1df76e8722a7cf";
  private static final byte[] publicKeyMlDsa65ByteArray = Hex.decode(PUBLIC_KEY_ML_DSA_65_HEX);
  private static final Bytes PUBLIC_KEY_ML_DSA_65_BYTES = Bytes.copyFrom(publicKeyMlDsa65ByteArray);

  private static final String PRIVATE_KEY_ML_DSA_65_SEED_HEX =
      "84d1e8cb37e37dc5a172706588fd367a85e9b10669a791bff7a1d77c0661e379";
  private static final byte[] privateKeyMlDsa65SeedByteArray =
      Hex.decode(PRIVATE_KEY_ML_DSA_65_SEED_HEX);
  private static final SecretBytes PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES =
      SecretBytes.copyFrom(privateKeyMlDsa65SeedByteArray, InsecureSecretKeyAccess.get());

  private static final com.google.crypto.tink.proto.KeyData ML_DSA_65_PUBLIC_KEY_DATA =
      com.google.crypto.tink.proto.KeyData.newBuilder()
          .setTypeUrl(ML_DSA_65_PUBLIC_TYPE_URL)
          .setValue(
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      com.google.crypto.tink.proto.MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .setKeyValue(ByteString.copyFrom(publicKeyMlDsa65ByteArray))
                  .build()
                  .toByteString())
          .setKeyMaterialType(
              com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
  private static final com.google.crypto.tink.proto.KeyData ML_DSA_65_PRIVATE_KEY_DATA =
      com.google.crypto.tink.proto.KeyData.newBuilder()
          .setTypeUrl(ML_DSA_65_PRIVATE_TYPE_URL)
          .setValue(
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              com.google.crypto.tink.proto.MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(ByteString.copyFrom(publicKeyMlDsa65ByteArray))
                          .build())
                  .setKeyValue(ByteString.copyFrom(privateKeyMlDsa65SeedByteArray))
                  .build()
                  .toByteString())
          .setKeyMaterialType(
              com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
          .build();

  // Test case from https://www.rfc-editor.org/rfc/rfc8032#page-24
  private static final byte[] secretEd25519Key =
      Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  private static final byte[] publicEd25519Key =
      Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  private static final SecretBytes ED25519_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(secretEd25519Key, InsecureSecretKeyAccess.get());
  private static final Bytes ED25519_PUBLIC_KEY_BYTES = Bytes.copyFrom(publicEd25519Key);
  private static final ByteString ED25519_PRIVATE_KEY_BYTE_STRING =
      ByteString.copyFrom(ED25519_PRIVATE_KEY_BYTES.toByteArray(InsecureSecretKeyAccess.get()));
  private static final ByteString ED25519_PUBLIC_KEY_BYTE_STRING =
      ByteString.copyFrom(ED25519_PUBLIC_KEY_BYTES.toByteArray());

  private static final com.google.crypto.tink.proto.KeyData ED25519_PUBLIC_KEY_DATA =
      com.google.crypto.tink.proto.KeyData.newBuilder()
          .setTypeUrl(ED25519_PUBLIC_TYPE_URL)
          .setValue(
              com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                  .setKeyValue(ED25519_PUBLIC_KEY_BYTE_STRING)
                  .build()
                  .toByteString())
          .setKeyMaterialType(
              com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
  private static final com.google.crypto.tink.proto.KeyData ED25519_PRIVATE_KEY_DATA =
      com.google.crypto.tink.proto.KeyData.newBuilder()
          .setTypeUrl(ED25519_PRIVATE_TYPE_URL)
          .setValue(
              com.google.crypto.tink.proto.Ed25519PrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.Ed25519PublicKey.newBuilder()
                          .setKeyValue(ED25519_PUBLIC_KEY_BYTE_STRING))
                  .setKeyValue(ED25519_PRIVATE_KEY_BYTE_STRING)
                  .build()
                  .toByteString())
          .setKeyMaterialType(
              com.google.crypto.tink.proto.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
          .build();

  @BeforeClass
  public static void setUp() throws Exception {
    CompositeMlDsaProtoSerialization.register();
    MlDsaProtoSerialization.register();
    Ed25519ProtoSerialization.register();

    AesGcmProtoSerialization.register();
  }

  // Parameters correctness tests.
  private static final class ParametersSerializationTestPair {
    CompositeMlDsaParameters parameters;
    ProtoParametersSerialization serialization;

    ParametersSerializationTestPair(
        CompositeMlDsaParameters parameters, ProtoParametersSerialization serialization) {
      this.parameters = parameters;
      this.serialization = serialization;
    }
  }

  @DataPoints("parametersSerializationTestPairList")
  public static final List<ParametersSerializationTestPair> parametersSerializationTestPairList =
      createParametersSerializationTestPairs();

  private static List<ParametersSerializationTestPair> createParametersSerializationTestPairs() {
    try {
      return Arrays.asList(
          new ParametersSerializationTestPair(
              CompositeMlDsaParameters.builder()
                  .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                  .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                  .setVariant(Variant.NO_PREFIX)
                  .build(),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  CompositeMlDsaKeyFormat.newBuilder()
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .build()
                      .toByteString())),
          new ParametersSerializationTestPair(
              CompositeMlDsaParameters.builder()
                  .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                  .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                  .setVariant(Variant.TINK)
                  .build(),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  CompositeMlDsaKeyFormat.newBuilder()
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .build()
                      .toByteString())));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void serializeParseParameters_equal(
      @FromDataPoints("parametersSerializationTestPairList") ParametersSerializationTestPair pair)
      throws Exception {
    ProtoParametersSerialization serialized =
        MutableSerializationRegistry.globalInstance().serializeParameters(pair.parameters);
    Parameters parsed =
        MutableSerializationRegistry.globalInstance().parseParameters(pair.serialization);

    assertEqualWhenValueParsed(CompositeMlDsaKeyFormat.parser(), serialized, pair.serialization);
    assertThat(parsed).isEqualTo(pair.parameters);
  }

  // Public key correctness tests.
  private static final class PublicKeySerializationTestPair {
    CompositeMlDsaPublicKey key;
    ProtoKeySerialization serialization;

    PublicKeySerializationTestPair(
        CompositeMlDsaPublicKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("publicKeySerializationTestPairList")
  public static final List<PublicKeySerializationTestPair> publicKeySerializationTestPairList =
      createPublicKeySerializationTestPairs();

  private static List<PublicKeySerializationTestPair> createPublicKeySerializationTestPairs() {
    try {
      MlDsaPublicKey mlDsaPublicKey =
          MlDsaPublicKey.builder()
              .setParameters(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .build();

      return Arrays.asList(
          new PublicKeySerializationTestPair(
              CompositeMlDsaPublicKey.builder()
                  .setParameters(
                      CompositeMlDsaParameters.builder()
                          .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                          .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
                          .build())
                  .setMlDsaPublicKey(mlDsaPublicKey)
                  .setClassicalPublicKey(Ed25519PublicKey.create(ED25519_PUBLIC_KEY_BYTES))
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                      .setVersion(0)
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                      .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              CompositeMlDsaPublicKey.builder()
                  .setParameters(
                      CompositeMlDsaParameters.builder()
                          .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                          .setVariant(Variant.TINK)
                          .build())
                  .setMlDsaPublicKey(mlDsaPublicKey)
                  .setClassicalPublicKey(Ed25519PublicKey.create(ED25519_PUBLIC_KEY_BYTES))
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                      .setVersion(0)
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                      .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void serializeParsePublicKey_equal(
      @FromDataPoints("publicKeySerializationTestPairList") PublicKeySerializationTestPair pair)
      throws Exception {
    ProtoKeySerialization serialized =
        MutableSerializationRegistry.globalInstance().serializeKey(pair.key, null);
    Key parsed = MutableSerializationRegistry.globalInstance().parseKey(pair.serialization, null);

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.CompositeMlDsaPublicKey.parser(),
        serialized,
        pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Private key correctness tests.
  private static final class PrivateKeySerializationTestPair {
    CompositeMlDsaPrivateKey key;
    ProtoKeySerialization serialization;

    PrivateKeySerializationTestPair(
        CompositeMlDsaPrivateKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("privateKeySerializationTestPairList")
  public static final List<PrivateKeySerializationTestPair> privateKeySerializationTestPairList =
      createPrivateKeySerializationTestPairs();

  private static List<PrivateKeySerializationTestPair> createPrivateKeySerializationTestPairs() {
    try {
      Ed25519PrivateKey ed25519PrivateKey =
          Ed25519PrivateKey.create(
              Ed25519PublicKey.create(ED25519_PUBLIC_KEY_BYTES), ED25519_PRIVATE_KEY_BYTES);

      MlDsaPublicKey mlDsaPublicKey =
          MlDsaPublicKey.builder()
              .setParameters(
                  MlDsaParameters.create(
                      MlDsaParameters.MlDsaInstance.ML_DSA_65, MlDsaParameters.Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .build();
      MlDsaPrivateKey mlDsaPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              mlDsaPublicKey, PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES);

      return Arrays.asList(
          new PrivateKeySerializationTestPair(
              CompositeMlDsaPrivateKey.builder()
                  .setParameters(
                      CompositeMlDsaParameters.builder()
                          .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                          .setVariant(CompositeMlDsaParameters.Variant.NO_PREFIX)
                          .build())
                  .setMlDsaPrivateKey(mlDsaPrivateKey)
                  .setClassicalPrivateKey(ed25519PrivateKey)
                  .build(),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                      .setVersion(0)
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                      .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              CompositeMlDsaPrivateKey.builder()
                  .setParameters(
                      CompositeMlDsaParameters.builder()
                          .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
                          .setVariant(CompositeMlDsaParameters.Variant.TINK)
                          .build())
                  .setMlDsaPrivateKey(mlDsaPrivateKey)
                  .setClassicalPrivateKey(ed25519PrivateKey)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                      .setVersion(0)
                      .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                      .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                      .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void serializeParsePrivateKey_equal(
      @FromDataPoints("privateKeySerializationTestPairList") PrivateKeySerializationTestPair pair)
      throws Exception {
    ProtoKeySerialization serialized =
        MutableSerializationRegistry.globalInstance()
            .serializeKey(pair.key, InsecureSecretKeyAccess.get());
    Key parsed =
        MutableSerializationRegistry.globalInstance()
            .parseKey(pair.serialization, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.parser(),
        serialized,
        pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  @Test
  public void serializePrivateKeyWithoutAccess_throws() throws Exception {
    CompositeMlDsaPrivateKey privateKey = privateKeySerializationTestPairList.get(0).key;
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MutableSerializationRegistry.globalInstance()
                .serializeKey(privateKey, /* access= */ null));
  }

  @Test
  public void parsePrivateKeyWithoutAccess_throws() throws Exception {
    ProtoKeySerialization serialization = privateKeySerializationTestPairList.get(0).serialization;
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MutableSerializationRegistry.globalInstance()
                .parseKey(serialization, /* access= */ null));
  }

  private static List<ProtoParametersSerialization> createInvalidParameters() {
    try {
      return Arrays.asList(
          // Unknown output prefix
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              CompositeMlDsaKeyFormat.newBuilder()
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .build()
                  .toByteString()),
          // Invalid version
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              CompositeMlDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .build()
                  .toByteString()),
          // Unknown instance
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              CompositeMlDsaKeyFormat.newBuilder()
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .build()
                  .toByteString()),
          // Unknown classical algorithm
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              CompositeMlDsaKeyFormat.newBuilder()
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_UNKNOWN))
                  .build()
                  .toByteString()),
          // Invalid proto serialization
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL, OutputPrefixType.RAW, ED25519_PUBLIC_KEY_DATA.toByteString()),
          // Invalid type url
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              CompositeMlDsaKeyFormat.newBuilder()
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .build()
                  .toByteString()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @DataPoints("invalidParametersSerializations")
  public static final List<ProtoParametersSerialization> invalidParametersSerializations =
      createInvalidParameters();

  @Theory
  public void parseInvalidParameters_throws(
      @FromDataPoints("invalidParametersSerializations") ProtoParametersSerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> MutableSerializationRegistry.globalInstance().parseParameters(serialization));
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final List<ProtoKeySerialization> invalidPublicKeySerializations =
      createInvalidPublicKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPublicKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(1)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key value / malformed proto
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              ByteString.copyFrom(new byte[] {(byte) 0x80}),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown output prefix type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.UNKNOWN_PREFIX,
              /* idRequirement= */ 42),
          // Wrong key material type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // the key material in the ML-DSA public key is not MlDsaPublicKey
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(ED25519_PUBLIC_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // the key material in the classical public key is not SignaturePublicKey
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPublicKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPublicKey(ML_DSA_65_PUBLIC_KEY_DATA)
                  .setClassicalPublicKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                          .setValue(ByteString.copyFrom(new byte[16]))
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC)
                          .build())
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void parseInvalidPublicKeySerialization_throws(
      @FromDataPoints("invalidPublicKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MutableSerializationRegistry.globalInstance()
                .parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @DataPoints("invalidPrivateKeySerializations")
  public static final List<ProtoKeySerialization> invalidPrivateKeySerializations =
      createInvalidPrivateKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPrivateKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(1)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid proto serialization
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              ByteString.copyFrom(new byte[] {(byte) 0x80}),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid key material type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown output prefix type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(
                      CompositeMlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65)
                          .setClassicalAlgorithm(
                              CompositeMlDsaClassicalAlgorithm.CLASSICAL_ALGORITHM_ED25519))
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.UNKNOWN_PREFIX,
              /* idRequirement= */ 42),
          // Public key invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl(ML_DSA_65_PRIVATE_TYPE_URL)
                          .setValue(
                              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                                  .setVersion(0)
                                  .setPublicKey(
                                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                                          .setVersion(1)
                                          .setParams(
                                              com.google.crypto.tink.proto.MlDsaParams.newBuilder()
                                                  .setMlDsaInstance(
                                                      com.google.crypto.tink.proto.MlDsaInstance
                                                          .ML_DSA_65))
                                          .setKeyValue(
                                              ByteString.copyFrom(publicKeyMlDsa65ByteArray)))
                                  .setKeyValue(ByteString.copyFrom(privateKeyMlDsa65SeedByteArray))
                                  .build()
                                  .toByteString())
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType
                                  .ASYMMETRIC_PRIVATE)
                          .build())
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance in public key
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl(ML_DSA_65_PRIVATE_TYPE_URL)
                          .setValue(
                              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                                  .setVersion(0)
                                  .setPublicKey(
                                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                                          .setVersion(0)
                                          .setParams(
                                              com.google.crypto.tink.proto.MlDsaParams.newBuilder()
                                                  .setMlDsaInstance(
                                                      com.google.crypto.tink.proto.MlDsaInstance
                                                          .ML_DSA_UNKNOWN_INSTANCE))
                                          .setKeyValue(
                                              ByteString.copyFrom(publicKeyMlDsa65ByteArray)))
                                  .setKeyValue(ByteString.copyFrom(privateKeyMlDsa65SeedByteArray))
                                  .build()
                                  .toByteString())
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType
                                  .ASYMMETRIC_PRIVATE)
                          .build())
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid private seed value
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl(ML_DSA_65_PRIVATE_TYPE_URL)
                          .setValue(
                              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                                  .setVersion(0)
                                  .setPublicKey(
                                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                                          .setVersion(0)
                                          .setParams(
                                              com.google.crypto.tink.proto.MlDsaParams.newBuilder()
                                                  .setMlDsaInstance(
                                                      com.google.crypto.tink.proto.MlDsaInstance
                                                          .ML_DSA_65))
                                          .setKeyValue(
                                              ByteString.copyFrom(publicKeyMlDsa65ByteArray)))
                                  .setKeyValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                                  .build()
                                  .toByteString())
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType
                                  .ASYMMETRIC_PRIVATE)
                          .build())
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // MlDsaPrivateKey is not type MlDsaPrivateKey
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                          .setValue(ByteString.copyFrom(new byte[16]))
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC)
                          .build())
                  .setClassicalPrivateKey(ED25519_PRIVATE_KEY_DATA)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // ClassicalPrivateKey is not type SignaturePrivateKey
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.CompositeMlDsaPrivateKey.newBuilder()
                  .setVersion(0)
                  .setParams(compositeMlDsa65Ed25519ParamsBuilder)
                  .setMlDsaPrivateKey(ML_DSA_65_PRIVATE_KEY_DATA)
                  .setClassicalPrivateKey(
                      com.google.crypto.tink.proto.KeyData.newBuilder()
                          .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                          .setValue(ByteString.copyFrom(new byte[16]))
                          .setKeyMaterialType(
                              com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC)
                          .build())
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Theory
  public void parseInvalidPrivateKeySerialization_throws(
      @FromDataPoints("invalidPrivateKeySerializations") ProtoKeySerialization serialization)
      throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            MutableSerializationRegistry.globalInstance()
                .parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
