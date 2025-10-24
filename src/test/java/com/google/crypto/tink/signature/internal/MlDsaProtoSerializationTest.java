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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.MlDsaKeyFormat;
import com.google.crypto.tink.proto.MlDsaParams;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
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

@RunWith(Theories.class)
public class MlDsaProtoSerializationTest {

  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

  // From //tink/cc/signature/internal/ml_dsa_proto_serialization_test.cc
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
  private static final ByteString PUBLIC_KEY_ML_DSA_65_BYTE_STRING =
      ByteString.copyFrom(publicKeyMlDsa65ByteArray);

  // From wycheproof/testvectors_v1/mldsa_87_verify_test.json
  private static final String PUBLIC_KEY_ML_DSA_87_HEX =
      "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805";
  private static final byte[] publicKeyMlDsa87ByteArray = Hex.decode(PUBLIC_KEY_ML_DSA_87_HEX);
  private static final ByteString PUBLIC_KEY_ML_DSA_87_BYTE_STRING =
      ByteString.copyFrom(publicKeyMlDsa87ByteArray);

  // From //tink/cc/signature/internal/ml_dsa_proto_serialization_test.cc
  private static final String PRIVATE_KEY_SEED_HEX =
      "84d1e8cb37e37dc5a172706588fd367a85e9b10669a791bff7a1d77c0661e379";
  private static final byte[] privateKeySeedByteArray = Hex.decode(PRIVATE_KEY_SEED_HEX);
  private static final SecretBytes PRIVATE_KEY_SEED_SECRET_BYTES =
      SecretBytes.copyFrom(privateKeySeedByteArray, InsecureSecretKeyAccess.get());
  private static final ByteString PRIVATE_KEY_SEED_BYTE_STRING =
      ByteString.copyFrom(privateKeySeedByteArray);

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  @BeforeClass
  public static void setUp() throws Exception {
    MlDsaProtoSerialization.register(registry);
  }

  // Parameters correctness tests.
  private static final class ParametersSerializationTestPair {
    MlDsaParameters parameters;
    ProtoParametersSerialization serialization;

    ParametersSerializationTestPair(
        MlDsaParameters parameters, ProtoParametersSerialization serialization) {
      this.parameters = parameters;
      this.serialization = serialization;
    }
  }

  @DataPoints("parametersSerializationTestPairList")
  public static final List<ParametersSerializationTestPair> parametersSerializationTestPairList =
      Arrays.asList(
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .build())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .build())));

  @Theory
  public void serializeParseParameters_equal(
      @FromDataPoints("parametersSerializationTestPairList") ParametersSerializationTestPair pair)
      throws Exception {
    ProtoParametersSerialization serialized =
        registry.serializeParameters(pair.parameters, ProtoParametersSerialization.class);
    Parameters parsed = registry.parseParameters(pair.serialization);

    assertEqualWhenValueParsed(MlDsaKeyFormat.parser(), serialized, pair.serialization);
    assertThat(parsed).isEqualTo(pair.parameters);
  }

  // Public key correctness tests.
  private static final class PublicKeySerializationTestPair {
    MlDsaPublicKey key;
    ProtoKeySerialization serialization;

    PublicKeySerializationTestPair(MlDsaPublicKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("publicKeySerializationTestPairList")
  public static final List<PublicKeySerializationTestPair> publicKeySerializationTestPairList =
      createPublicKeySerializationTestPairs();

  private static List<PublicKeySerializationTestPair> createPublicKeySerializationTestPairs() {
    try {
      return Arrays.asList(
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
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
        registry.serializeKey(pair.key, ProtoKeySerialization.class, null);
    Key parsed = registry.parseKey(pair.serialization, null);

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.MlDsaPublicKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Private key correctness tests.
  private static final class PrivateKeySerializationTestPair {
    MlDsaPrivateKey key;
    ProtoKeySerialization serialization;

    PrivateKeySerializationTestPair(MlDsaPrivateKey key, ProtoKeySerialization serialization) {
      this.key = key;
      this.serialization = serialization;
    }
  }

  @DataPoints("privateKeySerializationTestPairList")
  public static final List<PrivateKeySerializationTestPair> privateKeySerializationTestPairList =
      createPrivateKeySerializationTestPairs();

  private static List<PrivateKeySerializationTestPair> createPrivateKeySerializationTestPairs() {
    try {
      MlDsaPublicKey noPrefixPublicKey =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      return Arrays.asList(
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey, PRIVATE_KEY_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey, PRIVATE_KEY_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
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
        registry.serializeKey(pair.key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    Key parsed = registry.parseKey(pair.serialization, InsecureSecretKeyAccess.get());

    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.MlDsaPrivateKey.parser(), serialized, pair.serialization);
    assertTrue(parsed.equalsKey(pair.key));
  }

  // Test failure modes
  @Test
  public void serializeMlDsa87Parameters_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.serializeParameters(
                MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX),
                ProtoParametersSerialization.class));
  }

  @Test
  public void serializePrivateKeyWithoutAccess_throws() throws Exception {
    MlDsaPrivateKey privateKey = privateKeySerializationTestPairList.get(0).key;
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.serializeKey(privateKey, ProtoKeySerialization.class, /* access= */ null));
  }

  @Test
  public void parsePrivateKeyWithoutAccess_throws() throws Exception {
    ProtoKeySerialization serialization = privateKeySerializationTestPairList.get(0).serialization;
    assertThrows(
        GeneralSecurityException.class, () -> registry.parseKey(serialization, /* access= */ null));
  }

  @DataPoints("invalidParametersSerializations")
  public static final List<ProtoParametersSerialization> invalidParametersSerializations =
      Arrays.asList(
          // Unknown output prefix
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()),
          // Invalid version
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()),
          // Unknown instance
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .build()),
          // Invalid proto serialization
          ProtoParametersSerialization.create(
              KeyTemplate.newBuilder()
                  .setTypeUrl(PRIVATE_TYPE_URL)
                  .setOutputPrefixType(OutputPrefixType.RAW)
                  .setValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                  .build()),
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .build()));

  @Theory
  public void parseInvalidParameters_throws(
      @FromDataPoints("invalidParametersSerializations") ProtoParametersSerialization serialization)
      throws Exception {
    assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
  }

  @DataPoints("invalidPublicKeySerializations")
  public static final List<ProtoKeySerialization> invalidPublicKeySerializations =
      createInvalidPublicKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPublicKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key value
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid proto serialization
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              ByteString.copyFrom(new byte[] {(byte) 0x80}),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Wrong key material type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown output prefix type
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(
                              com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_UNKNOWN_INSTANCE))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.CRUNCHY,
              /* idRequirement= */ 42));
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
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }

  @DataPoints("invalidPrivateKeySerializations")
  public static final List<ProtoKeySerialization> invalidPrivateKeySerializations =
      createInvalidPrivateKeySerializations();

  private static List<ProtoKeySerialization> createInvalidPrivateKeySerializations() {
    try {
      return Arrays.asList(
          // Invalid type url (which will cause the wrong parser being invoked, and that parser will
          // not accept this proto)
          ProtoKeySerialization.create(
              PUBLIC_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setVersion(1)
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Public key invalid version
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setVersion(1)
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Unknown instance in public key
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance
                                          .ML_DSA_UNKNOWN_INSTANCE))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
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
          // Invalid private seed value
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid key material type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PUBLIC,
              OutputPrefixType.RAW,
              /* idRequirement= */ null),
          // Invalid output prefix type
          ProtoKeySerialization.create(
              PRIVATE_TYPE_URL,
              com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                  .setPublicKey(
                      com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                          .setParams(
                              MlDsaParams.newBuilder()
                                  .setMlDsaInstance(
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_65))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_65_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_SEED_BYTE_STRING)
                  .build()
                  .toByteString(),
              KeyMaterialType.ASYMMETRIC_PRIVATE,
              OutputPrefixType.CRUNCHY,
              /* idRequirement= */ 42));
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
        () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
  }
}
