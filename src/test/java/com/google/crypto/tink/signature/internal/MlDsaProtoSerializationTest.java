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

  private static final String PRIVATE_KEY_ML_DSA_65_SEED_HEX =
      "84d1e8cb37e37dc5a172706588fd367a85e9b10669a791bff7a1d77c0661e379";
  private static final byte[] privateKeyMlDsa65SeedByteArray =
      Hex.decode(PRIVATE_KEY_ML_DSA_65_SEED_HEX);
  private static final SecretBytes PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES =
      SecretBytes.copyFrom(privateKeyMlDsa65SeedByteArray, InsecureSecretKeyAccess.get());
  private static final ByteString PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING =
      ByteString.copyFrom(privateKeyMlDsa65SeedByteArray);

  // From //tink/go/internal/signature/mldsa/mldsa_test.go
  private static final String PUBLIC_KEY_ML_DSA_87_HEX =
      "467079ba853507ac38bd883bffbd9100dd43a2b755c31d59f2459f09907450525e781539f5b1ac3dcb67bbceaaa08107e92524084199be4ca89b15b1e66c9c3eecf51a885a9559ef458ff47710e12b82e083bf05a7ccb91e4ec28c9bea51cc8c093ca88306b30adef37e3af8ebd73fa730d9470e4cda5125ceb91cef4959898f4da7768d774a9a32907112220f9e44b8bfbd40e3262e3c409483a325d5bdb3d9bb998c6b2bee793947fc733f93e75b2fd2b44624e75bd0d861427147d3f82779cfdf414842d5e3645a05c05157a8097c60116d2d33090ba6f72237df5e6cd6a99b34cf75fe3c72195444165f875de88dd24cf90bd91d61d49e8319e4214e6d321b4943b988fcea283a307d46144d4da2c3dcea3158a181141fb38528214245a159c836abc600fdd870826362c2988be73ceada985f5de1efa5f27e6f42da75d57ece95447e4734efdd7577a6792ae4e166b2ecba0bd4bf5d428581d4ba12b44d2d7e44006b7471e538af7bb83b0bc588a999568542be276dad6416c71bb3129ea0cb81eeab734d5692c2db0786017c3c583987fc1d207d9bade74c288d4efe08b169907702cb10698a0e04223da082e90c68b6d1e45e86f2585ae4f4b0f70b96c6b79900fe34fdeaee21125271b090e43ac7d5219f0baa95dd71f9435f5e7acfce0eaa6c0b948308553238fc5063b9f1cdd2a4fd938cd000edd91f3ea7b13fc8a795ee2066c6f963d8a90ec0ab323e5d22ddccfa63261ee0bd51ef06bf7eef0fc84d35289f717463887717d2bf4030e55a6fc086ac4adf07d946e77bea275cb94cecd869ef162972d0489237d1be2cbfac5b7e0c1a6b1420aeb114fa83bd7fdbfa4f44dae7cf893e54aeff340845d85072cfa7fe0eff63d4a1fb0817fe6a9aea8326e6e30b7a1ad4a7ebde2bbea83986a4a39fe531eec7d6186ca44a8a8481f2832f74c4089b4338ca0236e46c7c08b00225e00217f19d24083e3b65694451e97995dffab3254f39ec1fa61164f0ac8b40c2b9d05db2e1d618a4d45b589dd742a5d2964ecb6a00ab13794ec615b9ecdf2cf33cdc3074d50138e8e5cef99542e6586b854075452630767056d4ce60d27e9ba603ed10676a891729a9fe02e5341da78668276284ed2aa7dd002080b907c36c2e68f51b47b625513cc0ebb6de26d2bd9bdaa91faa504080b9d7bfa4c42b0ef1d7966f40e82fcbc0f1790b6a1ba240f061c5b2dc63e1339e960f1999a498b7e3e2ed9cc048f389dbf2a5d4b2841b2aa7ada38118dfbca25ec124eea44a7155b3e2812b6993b91bb6558b7fafefecbd4637a411cc363f098b674dbac2236825fedb722832ac6d7825cab66d9e27384a1d99f2c4ba87ed124a4df127fee2ae6e44e7b134ccdffcc83c43ceb6971541beacd798868d1606f289b823325f841627fa3425133332633ff1e96b0d61eee4a756cddee52faf8587f96df0036fd5ed4bfafa21acef1112874efce3dc3cf385cd39d0a5dc7fa5998d850136e4639505d7b53f6d7c1076f5677b731849d9e54a5f3edc51014dcd9e171d28355a4555e643752cc6ac459e570384215d14d9f18b2a3a9a43b6e60d098bd16e546922b3a8fb743940a15af7220d07ab41b376f78b24845b8f5d17d2ef95b2ea0c66731c11f2e6a5663d57225394cf7e274fdbec0cb10e29ed42b09dccb97cf7e4974b2b07222ac77d51b94fdc3850c220e61c1b2816e85725053f0973d04f02e58993ba4ca46bb40fe8f0609516c145a4b5668ef893735d02bc0e86572ae8027f4be99e024ab922bb310411eb3f90286c8de75a1def0faf118ff322d87a348efda4f0a6cca47a059d897219453913cfbabce4badf2396cbd0b08d2e2d9a6cdd00de2caccab4f9fa28ea099bd253bcef35bd9d45e20589219b86647afc6a58ac4e0c3d10aca039d455f27fca07e4393cc4fb5cbdfc71ed8c433501a8cb9a86faf81080b17bea367c84cb4ed076e1ce037faabff6d752127c6fde5f9f388369d69200b49453e3862c607551bbf17e8d729ebf231a058d0c13ca97a426d2f9e0b7b573e5f9702ae3c673c2495b188870073995d2cd7d7f2f59672ce97cc24a08b2ec0b1671330faf986720ee5146fe45198d6b9cb291dd4b11b0741db975694244b9d746f1e95e78cac2dfd20eb4bf34b67371fb7f4619dc2e5c687d1a519903a31bbf7de02cb6dc6e9337011f1520b992e65ebcfbbf1d843a8e41f9f1080a148764a86d893b34bd70902e04fc5bff58a4dc007655cfb641e424b7ff50b587981f1225df7808cfdd7d9d67d01a67dfd9f5f264c7c5731463cb215d7ec5ada0c79411fcbcfe7932b25a668f415bda6738dff5b35195ba3ab4d233075e3d14ecdc3b695c502dd2bc7644a59ee0dffda587345e9d917b5bc7014d44097ad326f409582af76c17ad066cf62f1cf3fb0d04da94918972661b34dda287d7d2b29fc901fac30dd789f2680d7d5d5734c8cb562916b86e5e626dda2158932299985e78b7c64114c25367e69514e856ecba8e2d631bae701870110b77f1fce7f34a7cbd94475557844d2201e40caf27dd47716361e3795880f388babed1049fc83e125d3f570ce32c11f309ad24407b5d8066e94c6580d8b59a33408333d6431cf19ee5364bbb9c155faff06bdf23e32543e27913984213f9be63ed8d929b1a743d7b760d9c8ce98299dd4fe6d8bb1313b5a2cef487bd032e1b82c5740ab2c4a380aa04237947e6ffa6e8f6d2cde7ea3eedbf4d2c4e94a17a57739166b3b22e19eeb21d812775d26416f7a52bed28631ba24fb05c271b4bbc08f7725bedd2018de9b521faf8808b3c3ea26c17a50bfb6eb3abc438d3abf7f214e42ec7bca0ffe935111e4761a2fcf7bf41895be662f90d258a879b85f4393cf41d94037c96eb9e8188ddc03e6904a97361971747b48bf9a1315894f75a2f77953f63dce7741b815bf56f6205776a42d97ea7de99748d8991346dbc18b0b61bb77267df6c42c17d5afa9f3d5f49eca689d1f962eb5635165c307090f9ceeb19c96fec4ac27c0fead4e986c89d805a6318cba05d0ae727a017b813bf6f1fed8e30fc5fa5278b88919e9e20e0631d40e338b7326b464ceb154a641f208162e2ba8dca3253a80c7ff651274bcbbf6412049a91213cb0108b889d1e0b1b59edc2d730c0e36c35e395375333f48155cf2a5020587aba95fc325c633bb46d511f9717d8a9b2f272988a9ec0c7c30978030775a6d33d0816c3de1bd7fa03f01de7a1a58e1f5cd7b9fdcb1bf54520fec8547cf50ab33565b7eb605e355beeda9306341f658cb97f0d6d43e6f502f4e3bd253738a3841868e954f5859f0d26eee0141300c2001e6dbbb8c598ebe72f0f58276ed92682b95c777e2054392b1cb399a9dae4e658e3af757aa80897e549e3d47c99daf602d4523cfb994ff5b102c5555ea31145e6c6ffff8bb72c4d7a91dc9d06f20a7ba19fdd93a4628aaa9c665b0cae98720d9681d1421ab0af82758efaa4b5489ec1d22900efe84b3bdb7b64d8268036273a21afa618d8ef46feca0a8468719c4ceb2ee0159a1599ccd1bc074bcca27c0b228428f7ce1e4b310ed753cfcf9de625cbe325e07a846d2a73bdc487f36b3b5c538f6b22f0d4db5c003732e12599989071f58522702dc1c902d8df391e19f17882c1c6";
  private static final byte[] publicKeyMlDsa87ByteArray = Hex.decode(PUBLIC_KEY_ML_DSA_87_HEX);
  private static final Bytes PUBLIC_KEY_ML_DSA_87_BYTES = Bytes.copyFrom(publicKeyMlDsa87ByteArray);
  private static final ByteString PUBLIC_KEY_ML_DSA_87_BYTE_STRING =
      ByteString.copyFrom(publicKeyMlDsa87ByteArray);

  private static final String PRIVATE_KEY_ML_DSA_87_SEED_HEX =
      "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E03";
  private static final byte[] privateKeyMlDsa87SeedByteArray =
      Hex.decode(PRIVATE_KEY_ML_DSA_87_SEED_HEX);
  private static final SecretBytes PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES =
      SecretBytes.copyFrom(privateKeyMlDsa87SeedByteArray, InsecureSecretKeyAccess.get());
  private static final ByteString PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING =
      ByteString.copyFrom(privateKeyMlDsa87SeedByteArray);

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
                      .build())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.RAW,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .build())),
          new ParametersSerializationTestPair(
              MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK),
              ProtoParametersSerialization.create(
                  PRIVATE_TYPE_URL,
                  OutputPrefixType.TINK,
                  MlDsaKeyFormat.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
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
                  /* idRequirement= */ 0x12345678)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PUBLIC,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PublicKeySerializationTestPair(
              MlDsaPublicKey.builder()
                  .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK))
                  .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
                  .setIdRequirement(0x12345678)
                  .build(),
              ProtoKeySerialization.create(
                  PUBLIC_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                      .setParams(
                          MlDsaParams.newBuilder()
                              .setMlDsaInstance(
                                  com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                      .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
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
      MlDsaPublicKey noPrefixPublicKey65 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey65 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_65_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      MlDsaPublicKey noPrefixPublicKey87 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
              .build();
      MlDsaPublicKey tinkPublicKey87 =
          MlDsaPublicKey.builder()
              .setParameters(MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK))
              .setSerializedPublicKey(PUBLIC_KEY_ML_DSA_87_BYTES)
              .setIdRequirement(0x12345678)
              .build();
      return Arrays.asList(
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey65, PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES),
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
                      .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey65, PRIVATE_KEY_ML_DSA_65_SEED_SECRET_BYTES),
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
                      .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.TINK,
                  /* idRequirement= */ 0x12345678)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  noPrefixPublicKey87, PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
                      .build()
                      .toByteString(),
                  KeyMaterialType.ASYMMETRIC_PRIVATE,
                  OutputPrefixType.RAW,
                  /* idRequirement= */ null)),
          new PrivateKeySerializationTestPair(
              MlDsaPrivateKey.createWithoutVerification(
                  tinkPublicKey87, PRIVATE_KEY_ML_DSA_87_SEED_SECRET_BYTES),
              ProtoKeySerialization.create(
                  PRIVATE_TYPE_URL,
                  com.google.crypto.tink.proto.MlDsaPrivateKey.newBuilder()
                      .setPublicKey(
                          com.google.crypto.tink.proto.MlDsaPublicKey.newBuilder()
                              .setParams(
                                  MlDsaParams.newBuilder()
                                      .setMlDsaInstance(
                                          com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                              .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                      .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
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
                  .build()),
          // Unknown output prefix for ML_DSA_87
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.UNKNOWN_PREFIX,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .build()),
          // Invalid version for ML_DSA_87
          ProtoParametersSerialization.create(
              PRIVATE_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setVersion(1)
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .build()),
          // Invalid type url for ML_DSA_87
          ProtoParametersSerialization.create(
              PUBLIC_TYPE_URL,
              OutputPrefixType.RAW,
              MlDsaKeyFormat.newBuilder()
                  .setParams(
                      MlDsaParams.newBuilder()
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
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
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
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
                          .setMlDsaInstance(com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                  .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING)
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
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
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
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
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
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
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
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
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
                                      com.google.crypto.tink.proto.MlDsaInstance.ML_DSA_87))
                          .setKeyValue(PUBLIC_KEY_ML_DSA_87_BYTE_STRING))
                  .setKeyValue(PRIVATE_KEY_ML_DSA_87_SEED_BYTE_STRING)
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
                  .setKeyValue(PRIVATE_KEY_ML_DSA_65_SEED_BYTE_STRING)
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
