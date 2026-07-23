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

package com.google.crypto.tink.jwt.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.testing.Asserts.assertEqualWhenValueParsed;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoKeySerialization.KeyMaterialType;
import com.google.crypto.tink.ProtoKeySerialization.OutputPrefixType;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.proto.JwtMlDsaAlgorithm;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
@AccessesPartialKey
public final class JwtMlDsaProtoSerializationTest {
  private static final String PRIVATE_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";
  private static final String PUBLIC_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey";

  private static final MutableSerializationRegistry registry = new MutableSerializationRegistry();

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_44_verify_test.json
  private static final String PUBLIC_KEY_ML_DSA_44_HEX =
      "db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac90b1111170a561290ae86b139"
          + "68f2506023c014ba09fa449a26e4e9d35595e73986506cc8790e4d07a94d6c736f7ae78cc5e3e3cf"
          + "025ce06a09252bef97fe92e94cbd107b1844d1a7c690d88bff9e9336f8f58e0bd5ee384de9c7ffbb"
          + "149a6fcd87c77288601d8843e28e0c7a60149d02ebc57b183c39888d98b61cd8ad48135ddb8a1666"
          + "743bb689f44c1a92d52017b6a8fa493eeb839dffb086a9a6c399b194a52f0e4164c96ff8a2a54337"
          + "de24350a866b5fe4195257778e72511221778f1eae5fa93ed3532f696b9b0767aded85f62ea31102"
          + "7c7f5fc4182dcd2864b1c26bd6dcf72ebdedf70471327be0ea1c2ae53e46489c6dbefa512a78fdd7"
          + "be0ad3ada16a7f7b1ece49817b44868a2cc234bfdba556c32cc92ec2c5e8a5d206f2e4ee372d4168"
          + "1e67d1b7e7b0061870c57f600fafca85f98aed8ce4ba76bba961f9ed56e563220d3ced853b6b28e7"
          + "527da0e0912bc932a23c8bab811429bbb4d49b2770bcda44abb932b11c0a5866409fce39fed2b459"
          + "c86c8f6e1ab0aefc5879503f4b21a49b4b2de6760c9b6aaf041144a656a26af39f4578e1d482ddc1"
          + "360ef751d9784b860ec373d415360fe99f32e126a2ac1243430e8bed1bc90b19b3d219c2712edcf8"
          + "1c44b4331f6421088e662b695e1fd8fa5091f616ab60af70f159b63368f1ac60d77b279ed47ef7f2"
          + "4ec2044bb6c2bc76d933ecd568f7e663392afc1d335abac6c03670adf87747dde90052f5cd45f7d3"
          + "0f43a4dc3c500ceb658fce235c171240baca1b5a14733d774b9416c540f53eb83481afc98344b12a"
          + "4309e6222b08d978430467497010314c6f6b8caf65361c216106395275a67d7500dbc120f7918c6f"
          + "8db7aa63fa965b4a22c70dc88f727d768ce2bfc7597fd470184e1c59a6b2e1204cc8c3d052c594d5"
          + "771e0ccc8cfb191f47038b1c0672f07caf4747562d3d76a9816fb1def1391cf0f05fcdbf2a0eb6c2"
          + "1ac24b26e74ee403133e80a79313ddb02c1fa386c6dd1d420195343e3a104aff6d60887f7304fa9e"
          + "3bb59bb55f820dd85b1445c54e9a38dc1c7f3b88eb36a9f48d13455e51c934825ff3cd8bedb2b542"
          + "2344120399eef83a360b83440ebdd8ea6e01c95159e3735bb4408500caa785ca4049891c7331c4ea"
          + "31ad9060ece768fd339e6904f88e27bad3b28845687be2cc9314f300fda56fe3ff2508e54c59123b"
          + "068f86fe00213d5af8da1b1735423ed688f097c306dbc121b81f532fcaf872d9f80596642295d6e4"
          + "bead478644081618ab903b39e9b5e7cc0b5f2742d8337b18d4ad4788db7443e946cafc1762a5da84"
          + "070e8c2fd86d6c633f0b44ee234ba11b9e1440c94a08d0437015279690405353059020fd2f58f15d"
          + "ab18754177244adfb81ceab79c7840bf3884a3d364afc8c453a425fd8c5378eaa7445f8c6256bfbd"
          + "03a66c53e8cf27e2c52f14ef3294afe79cda408f5dff933ca0211a78a4e3be3d9a932558ed71ed19"
          + "bbb57f87937fa3d4a78128491ff096a261045bdd186325c42caa8c7564195a4d2499a1c17d21a52d"
          + "1aacd221d9c8a1866963a20390f2fd43dcf56b308a1c01c38091fd3e04c12b695de497d48bcc268d"
          + "50cb0bed793b8e6937e8d533afd568521f1c9377a3804d38e785674d7ce868d289938e33dda6edc7"
          + "6d25b15fcb38852b7803cfe62f08d9fbd070957c4e6f134973964c9dc009985c8501e7d8f72e7ec2"
          + "85d5289fdd07f64d62acaa9737b039efa7a9d1d175577c6bcf9dddcf692877af38e75263bebe2453"
          + "155be61f0723c274388a532abe29dd7023e327085f4c9dda41839b7b3357ab9d";
  private static final Bytes ML_DSA44_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode(PUBLIC_KEY_ML_DSA_44_HEX));

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_44_sign_seed_test.json
  private static final String PRIVATE_KEY_ML_DSA_44_SEED_HEX =
      "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
  private static final SecretBytes ML_DSA44_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(
          Hex.decode(PRIVATE_KEY_ML_DSA_44_SEED_HEX), InsecureSecretKeyAccess.get());

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_65_verify_test.json
  private static final String PUBLIC_KEY_ML_DSA_65_HEX =
      "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9cf676aedd1067c"
          + "91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408"
          + "e261ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f"
          + "44bc37f3a00e32eefd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f"
          + "8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be178be354"
          + "05683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930"
          + "f9b26413b843b83f3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e"
          + "4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b"
          + "94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa8"
          + "55f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e"
          + "892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029f8f8b06e"
          + "874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa2747db9bc42f92"
          + "af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc2"
          + "0e49e8efd76f9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5"
          + "c51d48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb929bee9f"
          + "f5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a"
          + "239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f"
          + "6398d715350925f0e0501944409f32331a362bdaaafb3d8ce71c964332d6afb7e684f999"
          + "51246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b620"
          + "13965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e728"
          + "31cb06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0"
          + "c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65e34d848b"
          + "d4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b6"
          + "36afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a84"
          + "2701603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539"
          + "cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b772465228dc44b079178f9"
          + "b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd28"
          + "3f0eecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c"
          + "9d37f694996e989a49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d"
          + "324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf2"
          + "52577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd337"
          + "5e608e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf"
          + "29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df986391badf90"
          + "41c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa62473429"
          + "05995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042"
          + "d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c"
          + "483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a12e1336f24dfacbc"
          + "3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca2"
          + "03b2bcb43f8881638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9"
          + "d25733143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa1254c821"
          + "9c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9"
          + "d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e"
          + "20c2bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4"
          + "b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad"
          + "23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff"
          + "4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d24"
          + "5387da50f28dd778fb33ab88c0918feba3768c55bb1f07aec33cfeed33d6faa4d34fd722"
          + "7b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430268c1492"
          + "a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776"
          + "a37a1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa9038baeb"
          + "c35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2d"
          + "d5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867"
          + "bae249431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e"
          + "09e214797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87"
          + "173a18dc";
  private static final Bytes ML_DSA65_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode(PUBLIC_KEY_ML_DSA_65_HEX));

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_65_sign_seed_test.json
  private static final String PRIVATE_KEY_ML_DSA_65_SEED_HEX =
      "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
  private static final SecretBytes ML_DSA65_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(
          Hex.decode(PRIVATE_KEY_ML_DSA_65_SEED_HEX), InsecureSecretKeyAccess.get());

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_87_verify_test.json
  private static final String PUBLIC_KEY_ML_DSA_87_HEX =
      "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c"
          + "121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f"
          + "65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d3"
          + "3e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff125469e8c3387abd788b620e3"
          + "0c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630a701"
          + "9af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7cedd"
          + "d1c4ba20edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba"
          + "3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e459"
          + "0cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8b"
          + "b8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d9"
          + "2212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d01"
          + "2d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaa"
          + "fbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f"
          + "2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02"
          + "167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0a45c0bfddb428b837c32e875"
          + "5441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a"
          + "450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e"
          + "907c51b63dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8"
          + "827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefc"
          + "ff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9"
          + "dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a"
          + "03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa4"
          + "8ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d"
          + "84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031"
          + "b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a5"
          + "25ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abafeedb3c99045a1442"
          + "3507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58"
          + "792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de"
          + "20ed26739ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c"
          + "51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385"
          + "041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338"
          + "e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45"
          + "d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c31"
          + "0d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1ba"
          + "f144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1"
          + "e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02eabafe678f44925a3e60"
          + "5979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a91422857774c63c665"
          + "9096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320ca"
          + "ae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f"
          + "4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f"
          + "5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a53"
          + "6be980220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90"
          + "fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36"
          + "de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbb"
          + "e3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909e"
          + "b2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e"
          + "2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9fb7933f514b07b4f4e"
          + "3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268"
          + "acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e07"
          + "93083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44ed"
          + "c63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d4527"
          + "0591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a7403"
          + "7105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e1225"
          + "8a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d723"
          + "9c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646"
          + "b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce"
          + "869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b"
          + "70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f6953865c683215203ce9638"
          + "75c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cc"
          + "cdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec"
          + "51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f"
          + "92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529e"
          + "e18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c"
          + "30bfc7d915e9284a56248e81944392881666680d4991f04269ec9a83b24b458ed59a6c27"
          + "4de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb438"
          + "2a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b80"
          + "0d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e3"
          + "15aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd140"
          + "9a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1324e0df1d483"
          + "ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed3"
          + "5f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9"
          + "ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e80"
          + "5";
  private static final Bytes ML_DSA87_PUBLIC_KEY_BYTES =
      Bytes.copyFrom(Hex.decode(PUBLIC_KEY_ML_DSA_87_HEX));

  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_87_sign_seed_test.json
  private static final String PRIVATE_KEY_ML_DSA_87_SEED_HEX =
      "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
  private static final SecretBytes ML_DSA87_PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(
          Hex.decode(PRIVATE_KEY_ML_DSA_87_SEED_HEX), InsecureSecretKeyAccess.get());

  @BeforeClass
  public static void setUp() throws Exception {
    JwtMlDsaProtoSerialization.register(registry);
  }

  private static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Optional<String> kid;
    final Integer idRequirement;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        Optional<String> kid,
        @Nullable Integer idRequirement) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.kid = kid;
      this.idRequirement = idRequirement;
    }
  }

  @DataPoints("ml_dsa_test_vectors")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.of("custom_kid"),
        /* idRequirement= */ null)
  };



  private static JwtMlDsaAlgorithm getProtoAlgorithm(JwtMlDsaParameters.Algorithm algorithm) {
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return JwtMlDsaAlgorithm.ML_DSA44;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return JwtMlDsaAlgorithm.ML_DSA65;
    }
    if (algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return JwtMlDsaAlgorithm.ML_DSA87;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
  }

  private static Bytes getPublicKeyBytes(TestVector testVector) {
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return ML_DSA44_PUBLIC_KEY_BYTES;
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return ML_DSA65_PUBLIC_KEY_BYTES;
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return ML_DSA87_PUBLIC_KEY_BYTES;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + testVector.algorithm);
  }

  private static SecretBytes getPrivateSeed(TestVector testVector) {
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_44)) {
      return ML_DSA44_PRIVATE_KEY_BYTES;
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_65)) {
      return ML_DSA65_PRIVATE_KEY_BYTES;
    }
    if (testVector.algorithm.equals(JwtMlDsaParameters.Algorithm.ML_DSA_87)) {
      return ML_DSA87_PRIVATE_KEY_BYTES;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + testVector.algorithm);
  }

  private static JwtMlDsaParameters createParameters(TestVector testVector) throws Exception {
    return JwtMlDsaParameters.create(testVector.kidStrategy, testVector.algorithm);
  }

  private static JwtMlDsaPublicKey createPublicKey(TestVector testVector) throws Exception {
    JwtMlDsaParameters parameters = createParameters(testVector);
    Bytes publicKeyBytes = getPublicKeyBytes(testVector);
    JwtMlDsaPublicKey.Builder builder =
        JwtMlDsaPublicKey.builder().setParameters(parameters).setPublicKeyBytes(publicKeyBytes);
    if (testVector.idRequirement != null) {
      builder.setIdRequirement(testVector.idRequirement);
    }
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(testVector.kid.get());
    }
    return builder.build();
  }

  private static JwtMlDsaPrivateKey createPrivateKey(TestVector testVector) throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    SecretBytes privateSeed = getPrivateSeed(testVector);
    return JwtMlDsaPrivateKey.create(publicKey, privateSeed);
  }

  private static ProtoParametersSerialization createProtoParametersSerialization(
      TestVector testVector) throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;
    com.google.crypto.tink.proto.JwtMlDsaKeyFormat format =
        com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .build();
    return ProtoParametersSerialization.create(
        PRIVATE_TYPE_URL, outputPrefixType, format.toByteString());
  }

  private static ProtoKeySerialization createProtoPublicKeySerialization(TestVector testVector)
      throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;

    com.google.crypto.tink.proto.JwtMlDsaPublicKey.Builder builder =
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .setKeyValue(ByteString.copyFrom(getPublicKeyBytes(testVector).toByteArray()));

    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      builder.setCustomKid(
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
              .setValue(testVector.kid.get())
              .build());
    }

    return ProtoKeySerialization.create(
        PUBLIC_TYPE_URL,
        builder.build().toByteString(),
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        outputPrefixType,
        testVector.idRequirement);
  }

  private static ProtoKeySerialization createProtoPrivateKeySerialization(TestVector testVector)
      throws Exception {
    OutputPrefixType outputPrefixType =
        testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID
            ? OutputPrefixType.TINK
            : OutputPrefixType.RAW;

    com.google.crypto.tink.proto.JwtMlDsaPublicKey.Builder publicKeyProtoBuilder =
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(getProtoAlgorithm(testVector.algorithm))
            .setKeyValue(ByteString.copyFrom(getPublicKeyBytes(testVector).toByteArray()));

    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      publicKeyProtoBuilder.setCustomKid(
          com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
              .setValue(testVector.kid.get())
              .build());
    }

    com.google.crypto.tink.proto.JwtMlDsaPrivateKey privateKeyProto =
        com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(publicKeyProtoBuilder.build())
            .setKeyValue(
                ByteString.copyFrom(
                    getPrivateSeed(testVector).toByteArray(InsecureSecretKeyAccess.get())))
            .build();

    return ProtoKeySerialization.create(
        PRIVATE_TYPE_URL,
        privateKeyProto.toByteString(),
        KeyMaterialType.ASYMMETRIC_PRIVATE,
        outputPrefixType,
        testVector.idRequirement);
  }

  @Theory
  public void serializeParseParameters_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    if (testVector.kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
      // Custom KidStrategy parameters cannot be serialized to proto parameters.
      return;
    }
    JwtMlDsaParameters parameters = createParameters(testVector);
    ProtoParametersSerialization expectedSerialization =
        createProtoParametersSerialization(testVector);

    ProtoParametersSerialization serialized = registry.serializeParameters(parameters);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaKeyFormat.parser(), serialized, expectedSerialization);

    Parameters parsed = registry.parseParameters(expectedSerialization);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void serializeParsePublicKey_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    JwtMlDsaPublicKey publicKey = createPublicKey(testVector);
    ProtoKeySerialization expectedSerialization = createProtoPublicKeySerialization(testVector);

    ProtoKeySerialization serialized = registry.serializeKey(publicKey, /* access= */ null);
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaPublicKey.parser(), serialized, expectedSerialization);

    Key parsed = registry.parseKey(expectedSerialization, /* access= */ null);
    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Theory
  public void serializeParsePrivateKey_succeeds(
      @FromDataPoints("ml_dsa_test_vectors") TestVector testVector) throws Exception {
    JwtMlDsaPrivateKey privateKey = createPrivateKey(testVector);
    ProtoKeySerialization expectedSerialization = createProtoPrivateKeySerialization(testVector);

    ProtoKeySerialization serialized =
        registry.serializeKey(privateKey, InsecureSecretKeyAccess.get());
    assertEqualWhenValueParsed(
        com.google.crypto.tink.proto.JwtMlDsaPrivateKey.parser(),
        serialized,
        expectedSerialization);

    Key parsed = registry.parseKey(expectedSerialization, InsecureSecretKeyAccess.get());
    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }

  @Test
  public void serializeParameters_customKidStrategy_throws() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> registry.serializeParameters(parameters));
    assertThat(e)
        .hasMessageThat()
        .contains("Unable to serialize Parameters object with KidStrategy CUSTOM");
  }

  @Test
  public void parseParameters_wrongTypeUrl_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            "wrong.type.url",
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("No Parameters Parser for requested key type");
  }

  @Test
  public void parseParameters_invalidProto_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL, OutputPrefixType.RAW, ByteString.copyFrom(new byte[] {(byte) 0x80}));

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaKeyFormat failed: ");
  }

  @Test
  public void parseParameters_invalidVersion_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(1) // Invalid version.
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaParameters failed: unknown version");
  }

  @Test
  public void parseParameters_invalidOutputPrefixType_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.CRUNCHY,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Invalid OutputPrefixType for JwtMlDsaKeyFormat");
  }

  @Test
  public void parseParameters_unknownAlgorithm_throws() throws Exception {
    ProtoParametersSerialization serialization =
        ProtoParametersSerialization.create(
            PRIVATE_TYPE_URL,
            OutputPrefixType.RAW,
            com.google.crypto.tink.proto.JwtMlDsaKeyFormat.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA_UNKNOWN)
                .build()
                .toByteString());

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> registry.parseParameters(serialization));
    assertThat(e).hasMessageThat().contains("Unable to parse algorithm");
  }

  @Test
  public void parsePublicKey_wrongTypeUrl_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "wrong.type.url",
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(new byte[1312]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("No Key Parser for requested key type");
  }

  @Test
  public void parsePublicKey_invalidProto_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaPublicKey failed: ");
  }

  @Test
  public void parsePublicKey_invalidVersion_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(1)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(new byte[1312]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Only version 0 keys are accepted");
  }

  @Test
  public void parsePublicKey_tinkPrefixWithCustomKid_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(ML_DSA44_PUBLIC_KEY_BYTES.toByteArray()))
                .setCustomKid(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.CustomKid.newBuilder()
                        .setValue("custom")
                        .build())
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.TINK,
            /* idRequirement= */ 1234);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e)
        .hasMessageThat()
        .contains("Keys serialized with OutputPrefixType TINK should not have a custom kid");
  }

  @Test
  public void parsePublicKey_invalidOutputPrefixType_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PUBLIC_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                .setVersion(0)
                .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                .setKeyValue(ByteString.copyFrom(ML_DSA44_PUBLIC_KEY_BYTES.toByteArray()))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.CRUNCHY,
            /* idRequirement= */ 1234);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("Unsupported output prefix");
  }

  @Test
  public void serializePrivateKey_noSecretKeyAccess_throws() throws Exception {
    JwtMlDsaPrivateKey privateKey = createPrivateKey(testVectors[0]);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.serializeKey(privateKey, /* access= */ null));
    assertThat(e).hasMessageThat().contains("SecretKeyAccess is required");
  }

  @Test
  public void parsePrivateKey_wrongTypeUrl_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "wrong.type.url",
            com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
                .setVersion(0)
                .setPublicKey(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                        .setVersion(0)
                        .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                        .setKeyValue(ByteString.copyFrom(ML_DSA44_PUBLIC_KEY_BYTES.toByteArray())))
                .setKeyValue(
                    ByteString.copyFrom(
                        ML_DSA44_PRIVATE_KEY_BYTES.toByteArray(InsecureSecretKeyAccess.get())))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("No Key Parser for requested key type");
  }

  @Test
  public void parsePrivateKey_invalidProto_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            ByteString.copyFrom(new byte[] {(byte) 0x80}),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("Parsing JwtMlDsaPrivateKey failed: ");
  }

  @Test
  public void parsePrivateKey_invalidVersion_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            PRIVATE_TYPE_URL,
            com.google.crypto.tink.proto.JwtMlDsaPrivateKey.newBuilder()
                .setVersion(1)
                .setPublicKey(
                    com.google.crypto.tink.proto.JwtMlDsaPublicKey.newBuilder()
                        .setVersion(0)
                        .setAlgorithm(JwtMlDsaAlgorithm.ML_DSA44)
                        .setKeyValue(ByteString.copyFrom(new byte[1312])))
                .setKeyValue(ByteString.copyFrom(new byte[32]))
                .build()
                .toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            /* idRequirement= */ null);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> registry.parseKey(serialization, InsecureSecretKeyAccess.get()));
    assertThat(e).hasMessageThat().contains("Only version 0 keys are accepted");
  }

  @Test
  public void parsePrivateKey_noSecretKeyAccess_throws() throws Exception {
    ProtoKeySerialization serialization = createProtoPrivateKeySerialization(testVectors[0]);

    NullPointerException e =
        assertThrows(
            NullPointerException.class, () -> registry.parseKey(serialization, /* access= */ null));
    assertThat(e).hasMessageThat().contains("SecretKeyAccess required");
  }
}
