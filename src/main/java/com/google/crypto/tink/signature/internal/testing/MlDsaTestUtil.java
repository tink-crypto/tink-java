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

package com.google.crypto.tink.signature.internal.testing;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaParameters.Variant;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/** Test utilities for ML-DSA. */
@AccessesPartialKey
public final class MlDsaTestUtil {

  private static SignatureTestVector createMlDsa65TestVector(Variant variant)
      throws GeneralSecurityException {
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            Hex.decode(
                "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a"
              + "5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682"
              + "a153aeadf228e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7"
              + "eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32ee"
              + "fd3a4bb1e298fe283d106eaef92a33a594253a2a0790976a1d04636f8672"
              + "d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7ea9be"
              + "178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed"
              + "0407cb0b975dd56d5930f9b26413b843b83f3693304b0038bd3e4bb39886"
              + "8060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c2"
              + "1ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03dd"
              + "b7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f8"
              + "27049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8d"
              + "a1aab29e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b"
              + "706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b"
              + "39cafe6e03e4edbafa2747db9bc42f92af8b031e3e380846b1bfd15ade88"
              + "c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f9568"
              + "bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d"
              + "48cc26358954514447881fd9a42e5891dac7e1db5249d7861b322111e5fb"
              + "929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9e"
              + "feceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e15df46a58280"
              + "bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944409f"
              + "32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c8674"
              + "4ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b6201396"
              + "5ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82"
              + "a6a0e72831cb06f9116cff5111d597e01057d32805a008f52c9aec331113"
              + "9bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e3357389fe"
              + "3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc2"
              + "05d3c6dab34d2b962b1afb44f1d22fc10c6744fcd6b636afd3cb414b16c2"
              + "e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701"
              + "603869d3ded572500f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf"
              + "755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb271416b77"
              + "2465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668"
              + "297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382"
              + "e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a"
              + "49075767ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f"
              + "9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c84e2"
              + "357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d"
              + "4f815c242b8e14acd3375e608e9230ba3cf8718f43882a3e1e661a2bbe81"
              + "830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd6273"
              + "8a64112deda5a2534fb0a23b3b3024df986391badf9041c593c313a7ca1e"
              + "1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa624734290599"
              + "5233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca326826"
              + "5c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc080fa7"
              + "b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0"
              + "f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b80"
              + "8fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f888163"
              + "8c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d257"
              + "33143e80a4cdde6770719c1e66ec2ce683612233e88fafff84c0745a98aa"
              + "1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65"
              + "fe0055b33fd6480dcbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2"
              + "dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449238f"
              + "7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04"
              + "fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0e57e6cad2387"
              + "5b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774c"
              + "a5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a"
              + "285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55"
              + "bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf"
              + "1cbd480d333ade1c9bb28308085b72ced430268c1492a27050c43668adc9"
              + "cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a"
              + "1f56fbf7d08e591f978da49c3870625879f70e2418aec5cba32fa8c346fa"
              + "9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f995aa"
              + "044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d"
              + "6edc55cec570a9c7372e29e02c8d4867bae249431dcf6ed2794a0183f0f7"
              + "501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455f"
              + "f47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f87173a"
              + "18dc"));
    SecretBytes privateSeed =
        SecretBytes.copyFrom(
            Hex.decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"),
            InsecureSecretKeyAccess.get());
    String signatureHex =
        "69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c286234471"
      + "3a1e9c086a44f9a870a3ccc14de62d6c12b278c354d7197c4d6d7f83d142"
      + "2b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d"
      + "7ed51f2463082d3f145cfd0fa7ac548a47e91c1ccb1a55b215e90ab355bf"
      + "c6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a"
      + "9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1f"
      + "b33f102e03373cdd192640f1027a08ce277b468f6ed0fe80a9d6cd2d6b2f"
      + "7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e800"
      + "1033c633bb1641ee66349487224dd43386c7fcc29916332066a868100d46"
      + "e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc"
      + "63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30"
      + "c94a2b98b67b471663e3d66326db3b43bebf958e8665b68eda90e8c5d949"
      + "4b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df6"
      + "1f752257ddf5a063b4a5b150371d625535e3b2874b9fe548960ff67931cd"
      + "6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3"
      + "f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f"
      + "51aacc0b304a62250bf2cae7b99dcd955b6596625d06da1c67f730b706fd"
      + "ba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b9"
      + "2e43143affae8b098e1d27716850f37553bf266cdfb561abbcdbfeb80752"
      + "b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25"
      + "140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd440770683"
      + "57c81d36e735eda4362930adead4951a0baa104f384fc70e842a9f329e18"
      + "68b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694"
      + "e5398860e439a1e19d5a66f2fbc0aacdd1a498711bb16054796c015a7153"
      + "95ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b"
      + "2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6"
      + "e09c2b0be0e37894888fe2812f68806f957c13fce6ff167bcee21d4f412e"
      + "c95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6"
      + "c59ff26fc38e1bb78a384b30e7b55f082e264d8f25e31518619ddd6b6a9f"
      + "af8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4"
      + "f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5"
      + "454697608326625fffe01bf87f44187dad631df2898effd2c291d98222e5"
      + "64abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5dd"
      + "eefd986c4bd3f99d877c2cc2381a89abdc61713d38cee58bf69805a485c2"
      + "88d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606b"
      + "f3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b7"
      + "4fca6500f6ed3d0736cdcc67d04f8fa9e80054a5bd7c8459fc1abb1c4c78"
      + "677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6"
      + "faec827cc41ec115ef3c2d7348cddabddfbc8436f3b41765e13f3762b3b4"
      + "5ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f"
      + "6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b66932"
      + "54649668aa91a1fa5eb7c59859bb6ddd36c25f4a2223f5d688b480d0388f"
      + "a307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc289"
      + "0b217bd6d11000a3a088cd837f4f8859a43f76afaaab05a0c3007a149d4d"
      + "6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b"
      + "8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e3221"
      + "99d37b4af83cbb3d98371c31be79bb42331e819644cbad2ce27a04e4c517"
      + "998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216e"
      + "aab399ef25b350ea213ba47126f278140e17391ca7139bd13c56f415e6b7"
      + "4aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e"
      + "35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c"
      + "137495eade0cf4d10fe621c73f01061acb077de72177ff5dbc6f0c5bec68"
      + "1aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da409"
      + "66703dcc2b33ae04f677677635a55db508f34f1403cdbe37960c8577dac3"
      + "d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87"
      + "efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa243"
      + "84d812db90fe74e0f93fda005eea87400736cabc036f71421b6657b1674d"
      + "4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f1025"
      + "51a9d03f9ce3d8cc850c393c128bf8054bb55bb92ea31ec0706f083a9cf9"
      + "0424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b"
      + "64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1"
      + "381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5445ce518eee937074ff7"
      + "a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0d"
      + "ffe311484e95d68de77170c909c815828946aeeec7ede56bcf433e22fc63"
      + "a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4"
      + "088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b"
      + "79e21314a1f28ed624f61e5aaecf2269e5b027e1910ffddede52fad4e8da"
      + "224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c"
      + "07c9721ded9093be6ce7bc7da3ac8c932133a64396b822be92b088844991"
      + "596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b39"
      + "77b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d"
      + "221742b66e27d9ee2d9dd07f401bc22a62c8a9d8d3a290c63804991496aa"
      + "fa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002e"
      + "cea68f9c3ff76cade27ed15fd7835989d0abb197fe32f68636139a427106"
      + "44bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb"
      + "082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a"
      + "1f2e653b5474da277f1818048094ac9e0e1e0b20068d1c1ce5a114a4db71"
      + "95057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c8270"
      + "66d9c6dcc4a4179bc44ea9b88abe5124bf78b071e09e9af43f739a6e1030"
      + "091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003af"
      + "c7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400a"
      + "d145fdb28348d22b317ccec704c401f88db1af2a5348223f5cefd914e404"
      + "c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50"
      + "a374f541cfe5e4e923c82ec47e5b3d2c70ad6760c79cd5080b490bdc75f9"
      + "ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e"
      + "6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665"
      + "e1b16578751eaea89e126bf58044596e3188c7a9631017be1f2dcd7d6123"
      + "31832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903"
      + "b91e9a43e0b1f0ed1511b2eca2f4253fcfbd7d0faebf3680fbf0a45df231"
      + "544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fb"
      + "d825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8"
      + "ac4d1ded18f1a801b0bda8fe9a88098825ff3eef5c1fc68cbea143310b39"
      + "543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a"
      + "88f3713456b4cfd83b30cb6520b624aa09c812066a8cd542dc67e19e4c92"
      + "b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655"
      + "d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e5639942"
      + "57df57977e5f219b4879751de57ab0374b407a21adb4ba520bb35e7b7508"
      + "675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac0"
      + "3bc06c0ef3b02f7d8acd40919315206fb38e715139c9bd6f89a58634fe68"
      + "3df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd"
      + "753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325"
      + "b5a0201e9453f6f012fe72e829ee1c637fe30037a9212a31c6e713726a6c"
      + "d4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d84"
      + "8c0271856bfe659922408449858a81fa6583f062d96898d18ec53664f006"
      + "7eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee"
      + "4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981"
      + "decc7174f3ff70a35d8a180ee12ed0cbffd4e8d14eb503387e4959f702d4"
      + "293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e6"
      + "63993636c754ce2b3c3f6a6b6d0b161e777b8296d7dce7fd162970496494"
      + "d4f60716244a5a7fb7cee40e1d565e6566697e8f93000000000000000000"
      + "00000005101318212b";
    if (variant.equals(Variant.NO_PREFIX)) {
      MlDsaPrivateKey noPrefixPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.NO_PREFIX))
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          noPrefixPrivateKey,
          Hex.decode(signatureHex),
          Hex.decode("48656c6c6f20776f726c64"));
    }
    if (variant.equals(Variant.TINK)) {
      MlDsaPrivateKey tinkPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_65, Variant.TINK))
                  .setIdRequirement(0x12345678)
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          tinkPrivateKey,
          Hex.decode("0112345678" + signatureHex),
          Hex.decode("48656c6c6f20776f726c64"));
    }
    throw new IllegalArgumentException("Unsupported variant: " + variant);
  }

  private static SignatureTestVector createMlDsa44TestVector(Variant variant)
      throws GeneralSecurityException {
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            Hex.decode(
                "db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac90b11"
              + "11170a561290ae86b13968f2506023c014ba09fa449a26e4e9d35595e739"
              + "86506cc8790e4d07a94d6c736f7ae78cc5e3e3cf025ce06a09252bef97fe"
              + "92e94cbd107b1844d1a7c690d88bff9e9336f8f58e0bd5ee384de9c7ffbb"
              + "149a6fcd87c77288601d8843e28e0c7a60149d02ebc57b183c39888d98b6"
              + "1cd8ad48135ddb8a1666743bb689f44c1a92d52017b6a8fa493eeb839dff"
              + "b086a9a6c399b194a52f0e4164c96ff8a2a54337de24350a866b5fe41952"
              + "57778e72511221778f1eae5fa93ed3532f696b9b0767aded85f62ea31102"
              + "7c7f5fc4182dcd2864b1c26bd6dcf72ebdedf70471327be0ea1c2ae53e46"
              + "489c6dbefa512a78fdd7be0ad3ada16a7f7b1ece49817b44868a2cc234bf"
              + "dba556c32cc92ec2c5e8a5d206f2e4ee372d41681e67d1b7e7b0061870c5"
              + "7f600fafca85f98aed8ce4ba76bba961f9ed56e563220d3ced853b6b28e7"
              + "527da0e0912bc932a23c8bab811429bbb4d49b2770bcda44abb932b11c0a"
              + "5866409fce39fed2b459c86c8f6e1ab0aefc5879503f4b21a49b4b2de676"
              + "0c9b6aaf041144a656a26af39f4578e1d482ddc1360ef751d9784b860ec3"
              + "73d415360fe99f32e126a2ac1243430e8bed1bc90b19b3d219c2712edcf8"
              + "1c44b4331f6421088e662b695e1fd8fa5091f616ab60af70f159b63368f1"
              + "ac60d77b279ed47ef7f24ec2044bb6c2bc76d933ecd568f7e663392afc1d"
              + "335abac6c03670adf87747dde90052f5cd45f7d30f43a4dc3c500ceb658f"
              + "ce235c171240baca1b5a14733d774b9416c540f53eb83481afc98344b12a"
              + "4309e6222b08d978430467497010314c6f6b8caf65361c216106395275a6"
              + "7d7500dbc120f7918c6f8db7aa63fa965b4a22c70dc88f727d768ce2bfc7"
              + "597fd470184e1c59a6b2e1204cc8c3d052c594d5771e0ccc8cfb191f4703"
              + "8b1c0672f07caf4747562d3d76a9816fb1def1391cf0f05fcdbf2a0eb6c2"
              + "1ac24b26e74ee403133e80a79313ddb02c1fa386c6dd1d420195343e3a10"
              + "4aff6d60887f7304fa9e3bb59bb55f820dd85b1445c54e9a38dc1c7f3b88"
              + "eb36a9f48d13455e51c934825ff3cd8bedb2b5422344120399eef83a360b"
              + "83440ebdd8ea6e01c95159e3735bb4408500caa785ca4049891c7331c4ea"
              + "31ad9060ece768fd339e6904f88e27bad3b28845687be2cc9314f300fda5"
              + "6fe3ff2508e54c59123b068f86fe00213d5af8da1b1735423ed688f097c3"
              + "06dbc121b81f532fcaf872d9f80596642295d6e4bead478644081618ab90"
              + "3b39e9b5e7cc0b5f2742d8337b18d4ad4788db7443e946cafc1762a5da84"
              + "070e8c2fd86d6c633f0b44ee234ba11b9e1440c94a08d043701527969040"
              + "5353059020fd2f58f15dab18754177244adfb81ceab79c7840bf3884a3d3"
              + "64afc8c453a425fd8c5378eaa7445f8c6256bfbd03a66c53e8cf27e2c52f"
              + "14ef3294afe79cda408f5dff933ca0211a78a4e3be3d9a932558ed71ed19"
              + "bbb57f87937fa3d4a78128491ff096a261045bdd186325c42caa8c756419"
              + "5a4d2499a1c17d21a52d1aacd221d9c8a1866963a20390f2fd43dcf56b30"
              + "8a1c01c38091fd3e04c12b695de497d48bcc268d50cb0bed793b8e6937e8"
              + "d533afd568521f1c9377a3804d38e785674d7ce868d289938e33dda6edc7"
              + "6d25b15fcb38852b7803cfe62f08d9fbd070957c4e6f134973964c9dc009"
              + "985c8501e7d8f72e7ec285d5289fdd07f64d62acaa9737b039efa7a9d1d1"
              + "75577c6bcf9dddcf692877af38e75263bebe2453155be61f0723c274388a"
              + "532abe29dd7023e327085f4c9dda41839b7b3357ab9d"));
    SecretBytes privateSeed =
        SecretBytes.copyFrom(
            Hex.decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"),
            InsecureSecretKeyAccess.get());
    String signatureHex =
        "1aa69cb5ed35204534f25f40a17eb0d767f8981f5e7cec46d3bf3252bfc7"
      + "8e09d02ef0c82da6dde973611c849472890106158cb15ffa6ca891615e88"
      + "8efa0d2d8a121b75ca440228ad32991be34249620f158ffd6f74d7b03bf9"
      + "19218ce259b500808ec157ead67b56b79e9e6607eafb9227b8a30adbec08"
      + "7d35bc1aec2f1a0c4dd126dfcfb9fbf0bd74fb1e092495fa994ab5a7cd13"
      + "33281aafe834694a6dc11e889c762b5645638e172dfab3060031ebcdc1fd"
      + "455d5de6050bf71b074a4dd34af5ebf15487651f0f13e5d3cee231b9b347"
      + "810bfc418196df9d7231780c09171b9aae732bea27a1649d8c03220f417e"
      + "30a016b08ccb1d55c9337b4812e20e04523f5d29a760a01b3a80d7628552"
      + "1206481ee1e44df09a76913ba54ae50c8eb973a3ced73950fbf39c4c0c12"
      + "62a216821a442072c10cc82839ac57b898411be9e810f893272a2546ff7d"
      + "1d920f146210efc2b4528bc98a099a398302d301fc1dea31b3d8ff78246a"
      + "66f690ef536b68e02bd7ea23a5378930dde7f1beb51749896a7944e5a40e"
      + "6fbbb1f76c3fda09e32e0a58062c24cac7ddb8c1d2cbb352a81e336425c5"
      + "f551246db45ecd0ab29dac88cdebf51c60bebc2e27c974f56da12c1fec4f"
      + "5745850429b607f5ed7cd821f2c91fc2dda8c2c8e8ec278d1b2a5bf50ec7"
      + "0c5623fc681b4d1dccff96b324cb53ff97470f9de177c2006a89af8f1860"
      + "3a6d4ea2625794695fe79cd30318a1e76307a4c2a353db1e076ad9b609a2"
      + "489b94cb6dd821c3af31046bb7a5d43d190e09fce4969fe4e93c8393975e"
      + "64cb2d9c2294fc427ef5191c40937929b3b0e1b037e6b84cc0299d5af2b5"
      + "410118bfd88ef6491af6f21233390ca7a19f1576e6c5a10a673796905562"
      + "075047896e3a2379f64dfbbc12b9bfe64939c2d05efbc5f6e4b5ca69ce1e"
      + "d4b7d25e8c835b0612b33e13ed7a8a7233b4b3d58eead0bc4c841acb65a5"
      + "ec0ed45e2584c23c2a162392b5789c62358e4038864e20c10e10c67d940c"
      + "e78993178dbeb3de1fea1e50e7c29f4d7d938c3bfe50229ea040102f30d5"
      + "b3a64cb8e13420065d54a1ac50a77383bdff3cae2340ebf15a1557fde897"
      + "007c1b67d04f19431ca00cb0f08db87e90e166e0f4ce6fd69c6ecef1b3f7"
      + "0d9eb601b57a7bf931057c2afe2d3567b6bbec7891c664713385122fdd78"
      + "9c1d5a8a9cfd491f407c16d0b0c5dfc53a6862208e264b981bf2ddbdd1d7"
      + "db9729b5265c4c3868a947c982880bc55b786153b89ef3324067b35a928c"
      + "51236bcbe9f860ad9eee5644478f894a9fe78d26a5a17d482612f1cb9983"
      + "b864e6fba84591c0f73b7b27918819d2121d4af640f533e2939d3da0f0aa"
      + "6b9df80837a80165ae8b7579715192eb0f6cca78a43d8ad8d7abb56d816e"
      + "3af2de59b88bfdcf6767abfb043d3ae24223d05001953faa292671c57ade"
      + "1fe28988075ab8d14ac98363412bd694c40ae85b1f104afcd0f25aa590f5"
      + "7ba4f5dfdf613bf8594e3f54baadfdf50c0881af2475590758a23b7eee72"
      + "5513e4d1ea9f4630159c424a289f18a9879e5e173390f8e630f6ee2a6043"
      + "d82a1983dc97c7acfea3b0c03e27e865d810d012daeec28dc454f59334ed"
      + "f24627d435701d329ff5e68d19bbdca5ef7d5e00204fa947d08f81cb6484"
      + "cabe60989d2f61fbe70940f7e4f449b3fcb103a89143d74b15d72e7913dc"
      + "e9193a0b9c5a7b2a97bde6d7f396ae80b4b566f9f2e7345bc42ce3b00281"
      + "8e19f0f16416b850832cd02279ee8d58a381deaac09b1b4d4613f4d06680"
      + "5d2faea6716e015fe361c0526c6e4617a389ffdf930213c1dc0c4c905c31"
      + "06a7517dce7abea7a9341132f8ad98de3e42f6b75809fff38f6eeafb9739"
      + "8e79d50a5622338763c4e45a88ddda7fb87ab7f5cec61109fdc1c5d4a163"
      + "10275241fc34178028a49fd79581a05c3b6984eecd6cb9bd60a44da72600"
      + "f8f2604a4ff4578126194fb2269c8e6e71447445e8e80bf8c6063dbbf29c"
      + "7ded58abbc0d2eed347bf495b6a9cbe68585a594aa0e65834bfbcccc3f6b"
      + "f42fe4ef42d86232c3fb1412dd0b5f8a0489958f5c3b883bf7851337a35b"
      + "13dd2b6517626ff2d1064cd189beb402497dd6b8893d414dde7d1d51018c"
      + "7a83766a2d8a29b80e8f428237732f7ee5ba878163f0aa8af5b60533b4d4"
      + "621a38fdc54383acb3325b5e876e21483eddcc64c419596e656d1557be31"
      + "b530ea66054f79d4f4a755f9ee33c84fed5d552ec5e2eccd061cf4c4b5c3"
      + "c16a70a7baecccfc208d2430e78621c9ae5b0d080973b4e1df0a1f5c0415"
      + "db6d3c85f9ea9041e9a9abdde71d6776a522aa957f708b14a33eda10ebba"
      + "b93bb8ec2b7a04679f38eb44fc558ee698d3c6937e0e647dce898d7599fe"
      + "f6de32ae4d52adc722443610b2126559756aa36f3c79696b99be3d908f78"
      + "0fcbaef33b215693634d63ce2a0777dfbbc899d2be72efdbafbc10aefb26"
      + "a1a63cdcfda00235b34db723c91624ee5f939024dfedba0863ad08f64876"
      + "7d41fc7fd6b317c51f4b1b87e21e07d488c9423581f9bbdae43e4d32b37e"
      + "8283960524f9a601ab69f5cd7fb01c9a8a5c64fe863519a1e9f3426398f6"
      + "91a96e1748491b4e209fca2ab29481a674621c797614ba16fbfdfd1a4184"
      + "e7f84667e720e6bcd9debef32c2b9e891a6e3c0423158f539838d8413e9f"
      + "c707d5c65b23368b6edc95d9c3f8e20bbb844499311614945606c1487ef4"
      + "015d1e260fa8239abaa071be572163132bdb06ef21e31be0f9d4b6747134"
      + "e4842bedcd3bf53b0d6f054693bc428e9a715d5a32a79e6a3cb8b81faf2c"
      + "04087d8816752637a2fe11eacb38341e024848562a29d4585e4ee56552ce"
      + "9b1fad43b965a37bff8558921790ef0f4ac55bcac4327d1783f5e1e79bf0"
      + "1e96934bb4a8f5dd06c83bb70b2377189d622a106100f0cbdd38e34c0565"
      + "900c616561161b3261859133f83893feb22b0bafc82cf4f0dbafde0648e2"
      + "f86260e6e747034e5cb3ece98087fbf74179c6306f0c460b5d609b9b3a66"
      + "761472ee0b9dabb5dfa872d5c6bc9b33461a27b5427bd8833f874f479ecc"
      + "5f0a20304b9a75aacc82420a87af6469daaef53391ae8a25468e717dc47f"
      + "464fce45a31147c0c4e12ac2f834567e4005b0827d13b3ec80cd8b7a9074"
      + "36e6624c6c8ac6a80add35cfa1a28872fb65cb3fa46894d116a052f19b5f"
      + "e20c7ead10bd24d27ad2b5683f299d1193ec6d9ff3379f3b3e39cb999183"
      + "1f194af2041085508da4dcb7b8785cbdc4e04cf4d826d1ef4a11036e4c58"
      + "03c3aaa7669b4dd3bc12ff888984e9bbdace0e772ab59332b47300334757"
      + "677578808e90929697a9cecfd6ed1b303d4250738a97a0aabac6d91e283a"
      + "4b696f7181828493aec8cdcfe1eaecfc0227484957595badbcbfc8fa0000"
      + "00000000000000000000000000000000121f323e";
    if (variant.equals(Variant.NO_PREFIX)) {
      MlDsaPrivateKey noPrefixPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.NO_PREFIX))
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          noPrefixPrivateKey,
          Hex.decode(signatureHex),
          Hex.decode("48656c6c6f20776f726c64"));
    }
    if (variant.equals(Variant.TINK)) {
      MlDsaPrivateKey tinkPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_44, Variant.TINK))
                  .setIdRequirement(0x12345678)
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          tinkPrivateKey,
          Hex.decode("0112345678" + signatureHex),
          Hex.decode("48656c6c6f20776f726c64"));
    }
    throw new IllegalArgumentException("Unsupported variant: " + variant);
  }

  private static SignatureTestVector createMlDsa87TestVector(Variant variant)
      throws GeneralSecurityException {
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            Hex.decode(
                "903efbf16cd1f779825106f76de12df49ca4371b57117480702a1d94dd9c"
              + "2042bdda05359144230762a55d09aaf6961245e21b0d413dc2f39cf99532"
              + "7c6a1d52607bd9c3addf70d056361d8eb86c4b60fb7e0de5638e4255454c"
              + "d32eb48653f6a9047247233284953da6d5f65af1b59421673f6f9e89b58d"
              + "483c6a9d3fc4eac36cc3e489ca243f17dbcf0686b8b4dcc4a37078b7a8b2"
              + "8218777c5c223aba3123eaacd83ce2ed91ada7ee0efa23179f4457903417"
              + "eda5350c4f4bd856de0bc419c91b76e7de9074c8eb4434d6055d80ac55ba"
              + "276427fe3c844ec42bbd37ebc6cb142c6c1755f02f7f0c94631c987ec447"
              + "060898b578144950e77cc51d9797df07025c8393ecb565c32eadd3179c69"
              + "6cb6ab5de99b8fcb623e8c59d836ae3d4e879cff4c4849880f0fbb293e7e"
              + "637d3897d47caa894656d58434244593d72a9781ff045a405f9c8886d1c2"
              + "b828467a9bc28c4e29aece6536abf539b02ab03c876d899376ccdda5c1ab"
              + "c4d3b2aaf3c5b3c7ad1956fcdb37f691e3e3dbb43ea967e733ec9e2d06d5"
              + "a0e9fd67af3020cbae5fcd7490e44f5e2646245fb1b92c93bfd694509324"
              + "6d490a1a0fcddd6d46bc4fa11137aa673d562488fa72cfb7fd210d3b3f04"
              + "794415826861e87c50fd9b297f0ebe32153b959d2ba684aa978827bebf6b"
              + "825c8c283388de6237ba4b51a0d47f01c57951809b9592c935c9acd64f45"
              + "d08d5207ba365ca2af7908c7791a4ecb8c20efded66ea640860293542479"
              + "7912e1363cb725c42deec98730fa99f17af4dbaa825159164878f5b97ffb"
              + "8959160ef304e5e1a10d7f8671454b81081d7e24a75922eaac49dd67c0ca"
              + "ac7e24d3f914ed64fe618e26860c6be09a6ba56100687b3f0a61ead9d55c"
              + "984107b1db88a1901abfb93b0c3556e4a3601e08bae9babafb177d61702e"
              + "0e8a357a2e760edd39cf7a3c601c022c629607bea771e408bed8c9678820"
              + "0f16f3f76f9fb89b4f04389d40b76ff720ce478bacd77e659359d3803bae"
              + "4be439fd4a212b38e169bc1a1cf9594fedf4a33ed7da7b3e1d853d055d45"
              + "c85b817805d25b59b52879b1eb7d59b723d05afbf9f62fb1384a12748b09"
              + "65feaf5ccc5f45162f173836d87b25907c262aa247c198e7edfe7a472bc6"
              + "553843e14c39e70dc993e566f0c339108fdf32a7c9c9186a09bd5773b3d3"
              + "393caf8f8d3ccc2edb7ba08ffa76c918669560cc170f69ca41614abfe6d2"
              + "30ac167a8f74f6664a23179580796ec0c01269ba2fef895b36ec666e750d"
              + "ce0f76bb411867ec5152ef5b1a1ae2a857d791147ec9bf50d4b1e9356281"
              + "2787c7cd07b8ed8ccbc294ec0721775c69731b3b471ba1621cd5bdfd11d5"
              + "ca1d38ead2a5b565d617a84d08ff1f4ad5bee0470d09b67c8d24c9018eb1"
              + "3205e6c86049b50c5de2c52345e015732cf2ce1da9e5df6cf0f54256b4d1"
              + "d35e7193afaacf616e28e761d977abf2a54a3fe5d2823a275dca6360394f"
              + "0a7879ab61871bb8f15c9bf1d8990dd256fb7f07c90541fb2af3c264e24c"
              + "8dc24ba47f6e23c9c17ba3162cce979c063a47841a3d264cb8489082b3b1"
              + "266539abf7bb6d6c277064980799793656e1f56906ba4541c19a8969cae9"
              + "fb98ee76500a895df493fa7aa4d8c4cf2f6ac554aee05490c1cc888a8d9f"
              + "30f477ef76ddc191794f0e92d3feade9b09b1de64ed0eba2bfc82d6bfc69"
              + "3a48205310d32bddbdd48333ac81db32b404163e6a835a5dcc3308aa0936"
              + "f39e66cfd9173437b00bae28d6d4defc2ddad001e2a6e782bdefab164a21"
              + "4f36e95c307ca141a1f38d5efa943779e9d01a72100f5de76a072074286b"
              + "5c6739b805eeefba5639f2ee0880265ed091e4a2dec230cf7453f4bdec31"
              + "3e16297338a3e3f6e03c8fb1208909a46dad667d14bcb66f9d21573efcbd"
              + "3a4b2d8196c94eecc453d943c8b27d3e2bf9b7defc2d00efa3fd131bb481"
              + "70a263a76366b78bbcc0d807cb0dca4daa9948c8240b537ecc28fefc3ab6"
              + "0d88a3486a5fc15c4bc6ec099e17d3a6b7b2761ea86980189e0e606bc0b1"
              + "e971532e627ac167726902a9d44c50be24ffc34212b54dc596064e34b982"
              + "1e6ea5a63892f187901691f516649e7b01748af1867a42a63bab54bf5516"
              + "68d0825e64773752449c64ec20842e5b8c6760d3379137eb9b5caaaf4694"
              + "74aa9bb3c1f1a5c257363eb27be4c7bc5c890f5d9532975051f2c4d62d14"
              + "c0024289f240a6abde67c0896de2ebc84fcfe99cef7d15f79b221617d385"
              + "782f60564b0b5911ee2d1be5459058a37c578d0348d1c6e5976ded66b6bd"
              + "26d5ed78afc59561bc28c75fa4b5048aa59d7d7010e22293a14d27b7b6f2"
              + "ed3b8e5974be2e8e46850e30737896fa0a2104ef31ecb24ae8b16fb090aa"
              + "f578811a60d864711b8be1cb538f69a3af67ef47b81d50f07ddafb394373"
              + "f8c8678d938e618184955d14eab88d715e1cd22e33aaa7027378c392d76f"
              + "458463f28a7f365ee708eefeefddb261d0ec1f44eef0e0084dddfcd7dd4f"
              + "28019d9184091c6e2ff0dcea261da0ee746ab6ea802f63c1c374675b52b3"
              + "935b937eb7375ea28e3b5198c8fe2c9a677be319933d981a19505e557a2e"
              + "d6e007110f0d95689ed23f62f20525e0029e4789933136b6cd3644f4d63b"
              + "002a0b5942eab5ff7b858b40dc120d78bae089a65ee5c7128db3841df863"
              + "f476ac15029ec0147a0596d2293d1b5f48b13071822e2e8e9f525fff0837"
              + "32ba87719fe92f6b264d9950458bd2c499e45af0c6179b0f116210844306"
              + "ec289c478fa72f76a6ac46acc55a32c19b2827127fa1a6d6f36b1ef50ce6"
              + "7a458643caaf9b8a9fe3f28ebb7896520d14827f64ca7d6efd9b8599ede0"
              + "d32f9748387569abb52028e042efc659aede4ef4ee4b85ffcd17455a522a"
              + "df712c6675f46a3dbf341e6fc748cc19ce8306c1e3bb762f69b171446d36"
              + "e63a299d0d68b88ecee3d7fa919bf402ca3ebd46fad001bc250c8177cd43"
              + "aeef01d32417303b65728fd25dceb9f1289815c3132ec1e57a376f1c19d6"
              + "901c398c58a3d7da3ae23c399eb71fa31a86d1cda4940b624d28ac93da1e"
              + "9fac52026c3a110250b5e95f78229059aeb9703377671e47a09496f1dc33"
              + "3be19c537514ab5255a27838cb039cb7817d35c387f3a19e21437ee1cdd2"
              + "c7ef58830284eaf677dce2d21d4b1ed54e2b2b15977a983cf939a9f5ac55"
              + "98dd73e50a43cdb6bd4ca9f08b78cd9c96ced06554db1cf4a6749fd50b06"
              + "2c702a6a2ee9f6102d7e848254593e430ec9a659e0104602050b49b70c4f"
              + "182327f3ebbc4214fa6bd034e2222ca012b3bc288413f6ece618eaf3acf1"
              + "b0d9aa94a102da9b56329f4c808ac33d35af54e6d4c1d12e60734eb0289f"
              + "1674255ad4faca9644c36388e65c1da898e4cd6531e89592e1e57bb2988d"
              + "5788ebe1b013283dddfa346cda5b224f5f8beffac5ca521bc546aa3f1eec"
              + "b254c597314657dda91727ba42929b3993c3c44ed3ce00aa1af9b00cf9ee"
              + "fd7530acf29c50bd0706620372424f58bfb356d28ef5a8d90403c52d62dd"
              + "2f92a19b75e6c46cb4eac77a9102a6dcbb1dcea05a28688b94ed3966e956"
              + "4519580803795f038255ccf0ab91762898942afa38e4bf7839b3dec19d24"
              + "44d5237212e15a491d1f5636d41d0cc3751d96d856f1cd4bf2a3fe1ae816"
              + "8b2475d11051eb1980c39fe1"));
    SecretBytes privateSeed =
        SecretBytes.copyFrom(
            Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d"),
            InsecureSecretKeyAccess.get());
    String signatureHex =
        "a8df889472d431f08dc5a3a28166aa9dd9ac5a9cf18b7d3d91b27b68e26d"
      + "e52c194ce98a34507e30d20e587625beef61817b207d678e7d5bf006e681"
      + "556c2d8f01af7eabd9e86484296d99d471ce69d8dadeef53b2b84e53b094"
      + "9d7e0b13e0f7564e6fb2673f33d3fc8689e7fd3f23c27334a3a6a7da3e7e"
      + "aff481b2c3c48d22afa40ac10d7dbb45575d3089dc5b6041d0658f2f6d70"
      + "83a1f875f07fb5cac47273b3300371b7fea083cc1c3123b8ab5d58907481"
      + "c53636ffc5f3232fae529cb42a4ceb8dc59219c9b7854a3aeac6e0774dad"
      + "6bb16a7f2630f0eb003df02ca028cfce3f3db170f3a23a1103718f559538"
      + "c4e7e2e1df0e10326c164571e27d59162d10ace2fbf0df367e50f3a21a5b"
      + "020a65f4f48a247c218a147dbca59e203d462e01f18399a3b53e667461ac"
      + "1213a6b9424a2b053c3e8243a79b1afe6d4bd82aebdb15b4fe968a2cd207"
      + "ffe48e5d256f1b61d75a14efb6ad8bd299216b988bf964a569e2a8d07b9f"
      + "b91e16624673b5ec8d672a430cb683f3e58e1633b377245fbea9d1f5afb7"
      + "8e2a516fea762d3da847a61346bee2e0e6d77ffc0328a01d41c2c395baad"
      + "5953d037db755d57f9f82f7c8a0e9a586f0c5adabf965d9fea1baaf14d91"
      + "79a4d385dd9ba0db6f32672f2dd0c9a0a738cca27cb864b8e9706c599335"
      + "c3dc168b84277e3ad532c4730c799962093eb3e2d36a6ded42495cfdf846"
      + "7c48db277ad977777d2c0edd61d76777453a9fe173ff7250e8fc2200e45d"
      + "5f276d5b7ccb2385678359b2ed5a1eeb08506b52de9bd461ba2041d1d556"
      + "cf5265dba97050bb58c34a846f53c6ee20adfbc723d3af2d6e84a767060f"
      + "c309418b3a7dff86a2c0041b04fdd12ba3bba0583a4b7a35334afd0451d6"
      + "9f34f10af727184ec0f59d0cc088811dfcc180060f2d10cc4467caf54f4f"
      + "068a756416e40708274924c42d0003e9701af0bf5bec2ed18b441cb23f8f"
      + "e76bc0862ac3ad5c7dc06153c2cbba9a9fa7c50ccb2ac162ab0780ddd93c"
      + "4c0fed5cff981287b0a8fccc6df141edd94969d27eb491f808b30a20cd9b"
      + "934ad69dc7bbb685a7d4c9688d837de438d7e040acdd28c7adf3bd577bfd"
      + "95be0f1f2a9be0c79d76eb6eba8f883b779a68312d4e1bb3a79905c49ed0"
      + "750310324526bc7668461279b7e8eef56ade2f818b84960614b53380079e"
      + "bd3a9146ff1b57423ee7b946abb23b6ac2c6adb95edf412d041efb418737"
      + "f57caf04f5a4f90ff810dedec8a9083adb44fe9f7766c18fca8144bd5f52"
      + "551b003563dd0d6b4ce4b730896905f66fa7941f1e88b6ea74bfbb6577dd"
      + "df1796c49b7b8489d4c4ab46ba3b4b85bf9809bd2569281c5f24f7ef9e24"
      + "4f08e3cbda30617dc7a9e8c84c5e5294d5d53356c6fceeab677e711b9ffa"
      + "fc400c3f27548007c4a15bec899d8011930c638c244661b533c1c2a84e1b"
      + "7c46328500cdef3a73b045e6510d890dec59e9a6a252788af5a4a9050a5f"
      + "98c864406e8a0e80ad2e9d91d178782bb71d60596c68a5283ebfec1b7529"
      + "44916784ebf60c85661ea4540d558aeef9dd9d29e92250063ca95fdd962e"
      + "5aaaf717187ff20125fbf9edb8dd000a73f90f04118b2eb01a914f228a1a"
      + "370dcf174a5f5cc4bafc85230cdc02f6be71bd1fbbb43d6b4a696e8880d5"
      + "e6431595cedf320ad30bb010241131beaab242eadb178d46b277ddc0ef37"
      + "8b72b4f4f19f9cfd7fe7bd49fe6ee6f81fe4824e1555d9d16352d5e596cf"
      + "893a84eefa8dd5d70c196b3223674845b0b7f2a49bd4a79985253c5eb654"
      + "47db0338059b99c0fd643055d9d8f6ca1223dd2726d17f689cc147f8098c"
      + "ddfbab9241ad8ee87f9cdc07707b4acca17ce40b6fceb22dfaa960b41972"
      + "f43d3ffbb0f08fba95c1cbe6726b858f41ae2410fb0b83efbc9e003c6e03"
      + "1271051257e6a0826ed4de3c5c7bb175fdcb2f585513772996f9be130f6d"
      + "d636e8e99ef09d8772ea84024cd1274f7567c7743a067656430a0bb2dce4"
      + "4c2020d21298dcd04bc48a6fdaf97f0ef988cbff4e2344cb5f4194f84f2e"
      + "a2a0e16959eb6cf8751c2b0d5db52aa8f41526058118a5eeec802ecc11b8"
      + "8d3bc5c92feb99f754e48ecf49f8fc39036d1b49706b91b663523a5aedac"
      + "44b06301d35949548d008c0eba84b711733254ee72a6b40228a9699b6c5e"
      + "3a63c236b0941cfbc3ddbb39acbe3e23523b7e2d9686c46652d7e4d929f5"
      + "975251def9328fc14ca119865adc0e916da16cd0391335aae5df649b359a"
      + "a4591d986af5010c1ac9667a309f3cc79a19fb6aa020e72df50c1ae2ce60"
      + "052736a0bdd6356fcb3730e747304a0d0e7a7b59c3256f12576b6bbc4461"
      + "505d2b0e09da0a58d87e8cbca13d34f424dae99029a24928b3ce8dd9c794"
      + "b61fa8d4848fb49274022b3b70654b08b1f88b6d7da5046e667f92e41f81"
      + "70fb05a2b536a07da7f41bc4cb1ac3b0eb4d3af505e5cc2b4d98e4d9c430"
      + "21f8fec85428c2e475e5ae8ecf578bdeb4dd5eceb0042874b03c5f7932aa"
      + "7f2f1447a04d72034575477cf165ac5e93424ae66d0a04262b308f546c22"
      + "6a2cd7545db34eb8a98817d4414918fb634fc9d947a637a15c26dcfd5bc6"
      + "0b4d44f1a0b57759bf882bc33183689b979d64396d96ba3b75a6d6a7de95"
      + "784a6dfdeb310f2f21ac424e76bdce4810774831e4d2e14a28473d2eb412"
      + "0830e71a52975ba56c84198cc258c7748b936a0277138ab8ca6e62b29e80"
      + "c30abc0bc984d3da6869c035fb258a2513d695974ee647593d4dbbb8a6ec"
      + "c05c935fe634ba612b5d7d546ccc446f2f354e4257ed524fb35c42ef6221"
      + "be1757b3bc077bf64c93f0c443df81eea4b323006e557d4240708513086e"
      + "23081f0c13da054b47d62bd82c79bc17f2c488a386cc2456270dfd0ff3d3"
      + "724a181eb9ecbfcfcff63d6ab3d590099e3444e49ff7af6a79d9c2b112bb"
      + "cbe08a05dde98f750bc0ab5972f523297f5604e35dfd5ad0b57950d4126d"
      + "2bb10a1840a9c5ed7ca5f9c1a08f29e77712812f75138f60dcad014023b9"
      + "7301b53b04b870080ca3e2cfdc29c88ecabae877d6b6460be72f04de84ac"
      + "78ed50268d977b1b56b4ad7753bff23cbb6547ef7f997baa3212158fa5df"
      + "1fc9001d7c7d56ca8a6ff42cbd7fd77cae658fc5408ad8c255d11295d0e0"
      + "5763f4efbc108735402ee9cca174804e1db90ea18c88adba36f61647e787"
      + "1ef1203ab929e91cf257df81f82f4c1954c5d76afa01a1a68127aee1989a"
      + "f4b2f9afba67596443f60f2c4249036e96ae6fe2b383e90bc360f8f7c146"
      + "1a9f24fb0dc8ce57d2e7bb543e3f78c047e0f12d781086a782dd2d9b1335"
      + "97fbbf9ac5a444ab3c3523e176e97d5f6d82183b4252fa35db1d6c1a7dc5"
      + "66b1007f8e889aadba9e51d0fa662f10ad61b713378d2f22c2e7ab01b9b0"
      + "4c2dfa6748e523f01b7ef497439e24d9d0071fac7676fde2b56dce2394e2"
      + "cbc9cff55da7d23ffe0d6581d3e97bb2487add9b957f1db9d399bf84e156"
      + "4a0c92ebaac332ce2ebc291e8b5fd0f3734347b1d8b8c940d3b438a265cd"
      + "f36ad96dbf6254229b96fdd2cd585c1a7686055f8337395a9298d94fc834"
      + "8f73e41dc9870f1c8f325113579ce0fbb729ea270874395b81f23205d26d"
      + "2da922e997c509ac213411b667d06dc4ee0a699b8d1722af1903c6927eeb"
      + "aac3ae2ccf70a447c8bb7f48b3c7198ee933d01d560aaf42ec7468ea81ab"
      + "8559bb013844103cba500d1540393bfb911a5bd902d06b3b4bc0f7dc675b"
      + "c281e5e1e2ac0bc4b762ad18d4631bb3aca3db02ccc5d56432315d0e3fd1"
      + "c4c8eef48f9b534c1b7fe0e38000c1aa0d3d49a68be281bff3c1dc4923ee"
      + "62b44403221db2d456b2d078394483159197f43ad832c75606e0576fe026"
      + "8a0feee7646a6fc156d34de3c8b13a72ef26e33e7b6a41b567ab1cabc306"
      + "2a8ea10aabe1ffeba682e1b4aeba5dccbddeff105f11a35ae84b47b74892"
      + "3dc7538576712f1545a702ad7a7b6ef7da967c43278cf4d53e09d377f3cd"
      + "93624b33add34f51292e98da4a8729557f7a31129057eef37b89a88b0828"
      + "5d749e209d1ebe4bf97e06f8a46eebfc3a31c9fb0b0054b1bfaa47281fbf"
      + "312b59e8a4d8157595f8efa1e80350eb9ac16e1f300872b39f5fa42c742d"
      + "d695717078c3886f5cc2a93236ff51dadc1debe783ff7c287b7f4d3e9ed7"
      + "115dc7cd44488c29e982d65d1ce41ba065aa948c52b4cbec24cc3e3d6e81"
      + "39eca8003f609f0598daa983e5360187640ba411d9d5ed3ab8c790ae7488"
      + "7512ca90b0a96fd0cf45b4ca2f6de0e382c22599cd2ffdee6fd5aeca0a2f"
      + "29aaf069c61272f70df4a0d34ad3d2b3475cac8a832713465dc9de904f26"
      + "d0217115fb081ba0bc2a10c2455fd977674145a33bdfeddb4e4fb7152368"
      + "18f02a7c13c1197b97c86f103186bf5159701a5158a4e49dd24188d3bab5"
      + "137be43ff6c594b976c7a7f8c3c92a6410b0a6e748bd172b5c8ef327bc9a"
      + "8be9e379cfe12a64e40c97069cabecc57abcdb0c96fcee703566141138b3"
      + "5cd2295607384402ea4c1b9a6591dd6d3c303197baf0b78f2da9ff52b64d"
      + "0c0263e9d4eb5fd09ad3e35a775b14c54d4d6433f1dbac9c172e33050840"
      + "0710b783cbf8e96bd0b8262415527c37f408ca3b761237a08602225e8ef2"
      + "86e35b6b08c71240b50d2185bcbb47d75e3e73b2aa68218d53ba811ad506"
      + "bc99d71d3b6b2d35a0a9e34b7acba12948c08790107505b054b4a828c269"
      + "74056ede75c1baaed177a29ada44600b6bdabba2bb0e23e3b3ccff462143"
      + "a90144d4bbe6968293ee04171798fccf47ca45b5695c26df18fb2745817b"
      + "c249757e3613e8d771153d65de7b4b4b1594a0a9d30c907abbf7ddaab3b4"
      + "21a0e805702b89c4c60a0e4addc01c5a51843db066ec5f53d4bb2d70359b"
      + "2374e9d23de6a374bc8d4e01f4db24a1d455e8fec641b8c7f7e82b22c0f3"
      + "c195c9e87c6bf24dce92f3def54ae5b549ce8f095c09acb01b0f6619cc43"
      + "11444e3e4a07b9d8dd6dc9aca15e3df12ccbd315855240bce7aa6c1be580"
      + "69feca1a789c327ecba288aa5c52202f663305a405e759ab0e8dece984eb"
      + "ecd93d0bd64947339c139787362b7c1ee02640ffbd81a9eb6c90e1400a70"
      + "33c35cab822cbacbf6f3397c1195b1c6b05e9447f638e97143e0dbf14923"
      + "497154e20028c282a09f006db42c61e8ab94875c22940e9ed850fa633f64"
      + "0f57637871f1a890ba3e5635828ecf5f2bfd3f540062cf45e8727d053f56"
      + "d704b73f37e1b99d4eec5082850838af09fe53dec2c9e5607b095c49254e"
      + "0ee2eef40b05c677f5f9a70a424d1d67f1cad16293f6485f149d2be1a699"
      + "a37434246e2d9e4f3a9beead5e73aeed5a5a01e4a931cb60e5d3de433a17"
      + "e12615efa06d6b7ecf8487025574a09e077aa20832e2ea292c0249fbf5c3"
      + "f79c4e01e90fd18741786a33314835eaad8c46dd2dd1380db32abf3dbb5b"
      + "0f0883a34aa8b23b4404432b6d2893be1c47a71454f9e429f918fc87cc1a"
      + "0d02cb29f604937afbdcdee937aa67501e9bf113ab08518501865d6c53be"
      + "1e4759a9784c55147b5a83aa764b67913d52cec438e0f3af142f82a3fd6b"
      + "9247611070416fe14f51d65e54d34aad84796497b057b7a45fc59eef8d74"
      + "ba4ee47e4e6ae426ae060d251928d9e98132944abe1fae99ac1218a643a9"
      + "82773ed242b342892f1660024bd5848b52425932a67395732db81a1de275"
      + "0869555374d4930cac5ed2ebfde371bb562f1d29e69b928bcddca10b3070"
      + "99212261142823357bbccb0e26c6503da192135ee95fffd4eabbece9e9de"
      + "ea4e3165f178b3bb65486ec2d31ec54b93c0fc5831743bd11e8464dbe413"
      + "a09cf83a805cd3de2e2198c66f27a9ed21974fdbaea8d12eff499ca8abc2"
      + "b437bdf6bd7a11c33f07143a52d21b72c9af1c001fe8857cdae2e3d90e07"
      + "0f4cef17058e3171f21983d91b77d3a86c93289b4d4362d67c2b6942913b"
      + "ef11bdec22193331ae578b4c6826552a393cd07d69a1f0075d7d2c2683d8"
      + "048582c46a3d2f52f1b8916534e2f565cd0c848aa469617d08ed4b31c631"
      + "0d37ae89f9b69a56603b9c0b6e2ab97d0f9ef5989875d5abe0b3048af3a7"
      + "8265827c5de2933072283b1bbbffa7bbdb04371f5b88634ed9184d3d68eb"
      + "1e5124d4d7e0517a4f92cf638deaf4910bbfaf5f58db78a5aa5f6c0d1dd4"
      + "8fad3e2b9d8c2491f304468f8249ed5ab8f46899f6e9d976fa35fdda90fe"
      + "5399e130313cdaa4577fb00e9aba9570c894d77725ed11dfabb1dbb93000"
      + "8ff9a1042d3ca268f8b00f5f4c2dc0df84ed00eeba642d1606f3826cb99a"
      + "c5f7eb197c9244a7937799d66dfb211103fbe769546ef8675fde9d8d01bd"
      + "790c3bf43775f950ce131966f6819881f976d764db5ec3902fd645f8234f"
      + "d4423043c2d2fbfb1478fe4d8c2877866f6d7fd88f4eee5a9bb9783b25c0"
      + "b40c91532abc1207b251ad86751a2d3298a3eb1a9faafa182445519daaac"
      + "bf19666aa6bdc0e2f808bcd0e3f4fc495e8caccfd2dfebf1f7f908445d96"
      + "b1b4c5c91d637175bc000000000000000000000000000000000000000005"
      + "0911191f2a3237";
    if (variant.equals(Variant.NO_PREFIX)) {
      MlDsaPrivateKey noPrefixPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.NO_PREFIX))
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          noPrefixPrivateKey,
          Hex.decode(signatureHex),
          Hex.decode(
              "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8"));
    }
    if (variant.equals(Variant.TINK)) {
      MlDsaPrivateKey tinkPrivateKey =
          MlDsaPrivateKey.createWithoutVerification(
              MlDsaPublicKey.builder()
                  .setSerializedPublicKey(publicKeyBytes)
                  .setParameters(
                      MlDsaParameters.create(MlDsaInstance.ML_DSA_87, Variant.TINK))
                  .setIdRequirement(0x12345678)
                  .build(),
              privateSeed);
      return new SignatureTestVector(
          tinkPrivateKey,
          Hex.decode("0112345678" + signatureHex),
          Hex.decode(
              "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8"));
    }
    throw new IllegalArgumentException("Unsupported variant: " + variant);
  }

  /**
   * Returns a valid signature test vector for the given ML-DSA {@code parameters}.
   */
  public static SignatureTestVector getMlDsaValidSignatureTestVector(
      MlDsaParameters parameters) {
    try {
      if (parameters.getMlDsaInstance().equals(MlDsaInstance.ML_DSA_44)) {
        return createMlDsa44TestVector(parameters.getVariant());
      }
      if (parameters.getMlDsaInstance().equals(MlDsaInstance.ML_DSA_65)) {
        return createMlDsa65TestVector(parameters.getVariant());
      }
      if (parameters.getMlDsaInstance().equals(MlDsaInstance.ML_DSA_87)) {
        return createMlDsa87TestVector(parameters.getVariant());
      }
      throw new IllegalArgumentException(
          "Unsupported instance: " + parameters.getMlDsaInstance());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private MlDsaTestUtil() {}
}
