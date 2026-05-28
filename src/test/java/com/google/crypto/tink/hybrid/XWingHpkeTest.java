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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.XWingHpkeConscryptDecrypt;
import com.google.crypto.tink.hybrid.internal.XWingHpkeConscryptEncrypt;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for X-Wing HPKE. */
@RunWith(JUnit4.class)
@AccessesPartialKey
public final class XWingHpkeTest {

  // Test vector from hpke_test_vectors.cc (CreateTestVectorXWing)
  private static final String PRIVATE_KEY_HEX =
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
  private static final String PUBLIC_KEY_HEX =
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

  private static final HpkePrivateKey HPKE_NO_PREFIX_PRIVATE_KEY =
      createHpkePrivateKey(HpkeParameters.AeadId.AES_128_GCM);
  private static final HpkePrivateKey HPKE_AES256GCM_NO_PREFIX_PRIVATE_KEY =
      createHpkePrivateKey(HpkeParameters.AeadId.AES_256_GCM);
  private static final HpkePrivateKey HPKE_CHACHA20POLY1305_NO_PREFIX_PRIVATE_KEY =
      createHpkePrivateKey(HpkeParameters.AeadId.CHACHA20_POLY1305);

  private static HpkePrivateKey createHpkePrivateKey(HpkeParameters.AeadId aeadId) {
    try {
      HpkeParameters parameters =
          HpkeParameters.builder()
              .setVariant(HpkeParameters.Variant.NO_PREFIX)
              .setKemId(HpkeParameters.KemId.X_WING)
              .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
              .setAeadId(aeadId)
              .build();
      HpkePublicKey publicKey =
          HpkePublicKey.create(parameters, Bytes.copyFrom(Hex.decode(PUBLIC_KEY_HEX)), null);
      return HpkePrivateKey.create(
          publicKey,
          SecretBytes.copyFrom(Hex.decode(PRIVATE_KEY_HEX), InsecureSecretKeyAccess.get()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean hasXWingSupport() {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance("XWING", provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @BeforeClass
  public static void setUp() throws Exception {
    HybridConfig.register();
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, we verify that the primitive creation fails.
    }
  }

  @Test
  public void create_failsInFips() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());
    Assume.assumeFalse(Util.isAndroid());

    assertThat(XWingHpkeConscryptEncrypt.isSupported()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptEncrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY.getPublicKey()));
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptDecrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY));
  }

  @Test
  public void create_failsOnAndroid() throws Exception {
    Assume.assumeTrue(Util.isAndroid());
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    assertThat(XWingHpkeConscryptEncrypt.isSupported()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptEncrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY.getPublicKey()));
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptDecrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY));
  }

  @Test
  public void create_failsWhenXwingUnavailable() throws Exception {
    Assume.assumeFalse(hasXWingSupport());

    assertThat(XWingHpkeConscryptEncrypt.isSupported()).isFalse();
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptEncrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY.getPublicKey()));
    assertThrows(
        GeneralSecurityException.class,
        () -> XWingHpkeConscryptDecrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY));
  }

  @Test
  public void testXWingAes128GcmHpkeDecryption_noPrefix_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    String plaintext = "4265617574792069732074727574682c20747275746820626561757479";
    String associatedData = "4f6465206f6e2061204772656369616e2055726e";
    String ciphertextHex =
        "c326b0c0a30963f331a4212415476bfbd888c8bcaa1b9cb9ed4975d54b0541a05753"
            + "f5b7cc62df29cf09152061f1dff1294e50ffa9efdf57ab0fd024a447150d1c152dda"
            + "8bfd2cb613f603823c67cfd20282ddecb7c4d8b676f33c864540317d5134c76c5295"
            + "9a26c037f09f9c3d74bb58bf969890398bfa71320e0a96e49c78f11dd5f2dc48bc0b"
            + "7b5a1bc0f66f9a4e85add8ac3a2f29c85689f83035a2a8586240c513354c860700c9"
            + "811af61c8ec6a384b5b00f385b9983bacf8a32c3fbb71ad56112844bdcc83a1b4be7"
            + "54b5b550b4e2d2c712ba85dab3de4c079547eb68d85b405fffc1bdfa5e163ceb5465"
            + "3c440e5bc6e34b454f710853edc704c1232cfa6042a5d7482c880bcc762ab269467e"
            + "198171280a9d9bdb37d450983a4f3f81b70f6848117a2c9667e8429f1976819e9476"
            + "0f5d8cfe4ef909c705cec742a6ef06426c9c7f498ce24e52415b3adcd28ef0e33479"
            + "367baa43979c295e88fd532b777ab48e9beb3e4374e8eeadba103edd5e250f92c962"
            + "42d6a18f811bbcbb67fc958f18a58d35cc37475bd384574fb69559b057faa8175b6f"
            + "436cb1751bfaccd7829db42be19c3e6f89f6db506a1f28a10c806b0df33fb1b8e789"
            + "c6c7537400afafb3a3beccdce24d47bc658e882f97ceb1a87ce0852a9e6db426b8fc"
            + "e667870412908f05b9768570dca927ddb05fb80f1242c5208434c83ffd8c20cb661f"
            + "b5c47b89017ecda1fa54cec5a7204d2092f57b7176fbbe3b8d0275337135a8cbf7d7"
            + "73042085d93348b6f622d19be14671fba1953fc6ba3df38a4fe317270efc3b1ed631"
            + "784bf2aaf777786f44a8b0677050f130a9b3377c5c269cbe83ded94aab71f6915c76"
            + "b307c623058020bbc498bf6f31b923454729a46286cad4eb2a1fbf7efe16c505abd4"
            + "9ad5a055ad0bd1ca405b1f7145c477f7f4903b90cd474618bb50aead90a3c88fcca7"
            + "5ebd8f1fa6274c3604c27374e4ea31973394d555442def7c222d2da4678c083771b0"
            + "8500d460906def458e1121e5d575ae8b21f2b0c6d99439ec39724f65debbbba504ec"
            + "fd9f957f8148a5d44db32cadfb6c81e931222080449f100a2f290b16a56eaa48ce43"
            + "7d6340ec0ba8519869aeff37f3dbefd7d67fb631132029fa880be3f59560d6d5b6f1"
            + "c84551d11acc02a0e2706c306936f578ac35f00440eeb593fc8efb6d387b1452e013"
            + "488bb6e0966ecd8ee0364bd16ad1df89bc1a6676b96ead983181d451ea2376a063b6"
            + "85d97e73d4d868552654690482e55f4547caafb0ea60634bc5b513216cb640b6baeb"
            + "d98d64e786b2f4972d6711b7e2995908ba43dd855f5fe4d59ee92efb87b59d120ded"
            + "c8bee364b713c32469533729ea37492890cab69099586082ce90cddff25aee364671"
            + "09f41b611ba0d4a5839e41f3a957a155d0a91eec26a5d51c651b22b259f4b4d23cc8"
            + "c3d5b8a4b1c324feb36d93d8a9a97bde22ffd8d3a934dd2154799fd34d0dc17b3e9e"
            + "45203e45257376ba800c2abe091ac424c6bebae649533603de6ccb51ed104412d739"
            + "8423a93e0301795d0074249828434d8252d3aa18cd6b428682e02051e6d2df08463d"
            + "106aaf2aa3f5528e1392d3b25bb52977b36af81bca74ec1a2a3b65cd14a8040c43f0"
            + "46d02f877aae69e2a8";

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);

    byte[] decrypted = decrypter.decrypt(Hex.decode(ciphertextHex), Hex.decode(associatedData));
    assertThat(decrypted).isEqualTo(Hex.decode(plaintext));
  }

  @Test
  public void testXWingAes256GcmHpkeDecryption_noPrefix_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    String plaintext = "4265617574792069732074727574682c20747275746820626561757479";
    String associatedData = "4f6465206f6e2061204772656369616e2055726e";
    String ciphertextHex =
        "e091314d69d0250e4c79366fcbcd812d9239db3431a2e44c44846146712580192e6a"
            + "aa528e437457c2d7cdb1c78c761451262580b29b81c66f07819661e0d9e1104eabb8"
            + "9a049664e2c0a2f6bf0adaf125059f5c43681df8a77357f79ba9612bece4d1c920f1"
            + "d2677a91337d6267c579c229dd1071087354ae86bf993f91c1762ccdd302d8fd8680"
            + "99411fe7d2ccfaeac036244881d6c02e77d2d60add9013a33abd3a1d500d6b6374dd"
            + "d2bbba00dc6fd3b971f869ad2973974a6dbec5de1c0877042c0001c6adede2bf0cf2"
            + "b2cb77e1018e0e4c4db3062f47d1e08848094c0e157ce723c1b10b6d9c3baff99bd3"
            + "36b124595e9581bfa9e51e9d802eeda16f16f50260cdccce1a9ed9c4e026b3f2a40e"
            + "4ddd3a53fab116771b077314b74188e139ed268ce749af80952e2e67bd04b8b3fe3d"
            + "5821dc16dc3267eccc0c3ee9195a8934b4bf8be66baa30ac08086f9d80cb260b6dcc"
            + "814ce61f783ffb013f5919aa6e80039403829156b31a2c54829961ffc451b744a05d"
            + "36c522836d731fb9afd82907c39f93439d6af8ca6d0f7406c1b252ca3e4b95ade048"
            + "562b13167be92d834ebbce3049e8450a33c47b06b8f749f5bac0d1cc0215677c7c59"
            + "6040e900b660ddf640cc299e5a4a5ce95afd1650799e27630138af3bba686dbf5f91"
            + "f9b9b1c4077a69d469e61fcb7308baa81a87b0a7df13acb7178af1a3d543d39a89d3"
            + "e26b6dcf4561d0cd5027881a09bcc5d759a5326581f5772ca958294119e292ae20c6"
            + "ea4897e802204f3432dc30c8b9e0c1c3417e932eeb8e8fd11e45bb6c499d34ec81fe"
            + "4afe27c85e381ebe0d3fda7b9ea99f38dd8a8370a1fe97d309d0f25b67eb1c8654de"
            + "b6029bcdc40ee26467c98cb90aebb39e622e82427d490201dd6ecbdc0948daf54918"
            + "34a35f71c9ff44b2fa7c9f15b33e4f560d435fca4b89663275e930d505067dc5b226"
            + "651f33ad56f5b1cad803076dd2c1bcfb4c5f90954f9ceb55835a50a163d8d3c03158"
            + "5a3949797b12c0d090e49dd8ea87bbdddce53251e026157d6f60bd053b69727589ed"
            + "178cef36276d471923a30676fb29e8bb03ece9a3dc7d2c9f5858b3004aaa4a8b1fa1"
            + "5c1371321229348ce93d32af7a8c819c8783212fe962d73ca30d35decc2503097d6a"
            + "ea205a11af8a30ea2bb6b5bf208133bf1b0dacfafffd350b96040e692e6ea18fe36f"
            + "8469419f10cca58f3bcb8b2d941f05325a484b413c72768dbde9ec63eac2b9f8aab4"
            + "644d959df2c6b9ab1cdef720caa7668dc40a65c4b7580673a01be3fe1c1b4f9a1d3e"
            + "b7ffdd008f4ea86ef00333cf414df769b6adcf5762005a29cf7c2007bd7017b8c7c1"
            + "c6a67963d07ccb9cc9f0442bdbbdac879ee2a6672ef569e28cd97e0d018c26a3ecda"
            + "3d21eb83ce13ff053a3d0e1941d36d2b9c1f274e31287495c70ea2cb4a0b62e10c65"
            + "96aa2b9a9ba4166cda79407ce042bb3f1ef845998fd60c019744654c06f41d4570b1"
            + "69b956dd0164270c30b7f0ebcf6e8d577b257c87446439d138fe49cbe9fa10a9ee05"
            + "3800787cb924bdcf8a9a919837edc747594677a12d2ef24e121591116052c8766351"
            + "4319041c8aa1472417eab182ba68b932575a40786cf6e3b5bee19b79049c8e93021d"
            + "fef49de0f37f7fa574";

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_AES256GCM_NO_PREFIX_PRIVATE_KEY)
                    .withRandomId()
                    .makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);

    byte[] decrypted = decrypter.decrypt(Hex.decode(ciphertextHex), Hex.decode(associatedData));
    assertThat(decrypted).isEqualTo(Hex.decode(plaintext));
  }

  @Test
  public void testXWingChaCha20Poly1305HpkeDecryption_noPrefix_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    String plaintext = "4265617574792069732074727574682c20747275746820626561757479";
    String associatedData = "4f6465206f6e2061204772656369616e2055726e";
    String ciphertextHex =
        "432460c6190c2b3c47792a0c7fef157106b84fe42dc3c614ec1cb137981a98aed918"
            + "fed29f640e7db9f0cb8c61c5574df64f7f6d61469cb25fe68b72d928271a205046d4"
            + "b15febf45959e2a3f826ddcf8edfed448c0963a44b95521c19267e1042ff61d5bfc2"
            + "3f0bcf28726ab182696d8a8c5ffc99224745ae638b993ed89386d7ae6749ec30a5f7"
            + "cbd23a41b2f821188360605bad25919ec1c6ed1c68a0ef0d7957fb8dc928b4c924ff"
            + "8559dd64ef5a631fe16a5ec0c5a8a6ac070edb715cea8b3d050a5c074b9298ee3d1f"
            + "83bbbe189cf8b659f3bc1dad50972e8917911e1c93a4827175f1a854f97dc69be7e2"
            + "e95002f5d8ce006207d13c96c3b04c2b2be0bdb0f154cb589533781fbb7eea9562ab"
            + "05024c7f50429ad36d6143205c30bb4454d0280d5d03ca8258dcd3e20e75c26441f6"
            + "bc4f2fd7568f27b171d22e12cb96ce5d7d840c3c78ff5a279d8d36d1b69de474778d"
            + "96f1a169598c625e3f784f885691bd3e22fcab2becb11f1334a0a5eb97075db15aeb"
            + "8989802ab7ee1bd2618789afe9959ef720f9bcf5018a0dc03b16ad4703a70bc21244"
            + "584adf6e6cf0b9cfbbb5c5511441030883ecb0e16468cf96101c35c635d54b7926c5"
            + "18bfb99877f96b7a598641eb5937f6d774295674d87d4c7947d2105b517e0356b331"
            + "c0c3dd06a662aea8616643566c09bfc964bd7cb130b2f8a50f6dd6b0ea69a6b3062d"
            + "0fee6c6ad3344429cf4f9ca9096f2cc3de4bd595379e27988a6e4379426dea5636c2"
            + "3b1621f21d509ed93bbd986bce754ac1e33b5708dbe4e685a3717b57eec0aaa59a1a"
            + "d616601030764bccd8e0c543f0c267c4e1d36206f4f523068fbc7295c4838a0f02f8"
            + "f47e6be8d7f677c6952745f74dd9acb98ee459833b562462793d5b364b2e80dcb95e"
            + "04f21099cdc110d6fc036f4ba116dbdb1812beceec700d16a962d077e038f5ff537f"
            + "c5ce28144afd5c17e18bc1a27788fd6b854ecca060356be7825d1715c92411c55e50"
            + "0468bfcd0f6bb9ec4f62d439f89c49b46b37d9169324e5978ac710089a3d8d697851"
            + "115a655940f5c2382168c2cc94e85e97769d7b6a1e92b09fc2d8604e863448b6f721"
            + "b0aa3b8a63c5dad37a22ed162e42eb176b89133544c1b13fc88df4d31d6b52fb8e60"
            + "466fa1ca3aed0557b7da395d9055fccc87d012bd73ffb706890d4ef81ed11ceda6f9"
            + "b437d3a677e0f1b5d27b6d1cca633c84f2118a1e1b554e4b7111b4afd7e350573d03"
            + "7df7a705ac57cdfbcc79ccf7365bc96bd331c539602e607b8fa7969afabfa9cad223"
            + "eaba063c7516612208fce19123c7c413429cfd50f1958c9facd71acc8809050ff96d"
            + "291fdcf388bf5387c7bf0a783c802efa45b09ee7fa9935e498fb5ee295fa11ae3f6f"
            + "3c731b7ab4510fde5af1e8940ae56768e0853683ae4769a62086a3787972428599b0"
            + "70ac8d51a039b4d30ba6015dcce84e58089e7885939367347bcf3af8552ae447ac52"
            + "20636a4e955b1dfa8578f3ea60154039fa4b1056e294a129e1c579d4f3469af5087f"
            + "807c74c95959736a2ee915daa03e60007c97245dcd7f7b635987a0ec175597240c9a"
            + "afb86527748118dcb9b08ebf14b65d02db4b32b3d0ab30dca75d9eb4851686fcd704"
            + "4bf19030b10a07bfc4";

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_CHACHA20POLY1305_NO_PREFIX_PRIVATE_KEY)
                    .withRandomId()
                    .makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);

    byte[] decrypted = decrypter.decrypt(Hex.decode(ciphertextHex), Hex.decode(associatedData));
    assertThat(decrypted).isEqualTo(Hex.decode(plaintext));
  }

  @Test
  public void testXWingHpkeDecryption_tink_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    String plaintext = "4265617574792069732074727574682c20747275746820626561757479";
    String associatedData = "4f6465206f6e2061204772656369616e2055726e";
    String ciphertextHex =
        "0112345678"
            + "c326b0c0a30963f331a4212415476bfbd888c8bcaa1b9cb9ed4975d54b0541a05753"
            + "f5b7cc62df29cf09152061f1dff1294e50ffa9efdf57ab0fd024a447150d1c152dda"
            + "8bfd2cb613f603823c67cfd20282ddecb7c4d8b676f33c864540317d5134c76c5295"
            + "9a26c037f09f9c3d74bb58bf969890398bfa71320e0a96e49c78f11dd5f2dc48bc0b"
            + "7b5a1bc0f66f9a4e85add8ac3a2f29c85689f83035a2a8586240c513354c860700c9"
            + "811af61c8ec6a384b5b00f385b9983bacf8a32c3fbb71ad56112844bdcc83a1b4be7"
            + "54b5b550b4e2d2c712ba85dab3de4c079547eb68d85b405fffc1bdfa5e163ceb5465"
            + "3c440e5bc6e34b454f710853edc704c1232cfa6042a5d7482c880bcc762ab269467e"
            + "198171280a9d9bdb37d450983a4f3f81b70f6848117a2c9667e8429f1976819e9476"
            + "0f5d8cfe4ef909c705cec742a6ef06426c9c7f498ce24e52415b3adcd28ef0e33479"
            + "367baa43979c295e88fd532b777ab48e9beb3e4374e8eeadba103edd5e250f92c962"
            + "42d6a18f811bbcbb67fc958f18a58d35cc37475bd384574fb69559b057faa8175b6f"
            + "436cb1751bfaccd7829db42be19c3e6f89f6db506a1f28a10c806b0df33fb1b8e789"
            + "c6c7537400afafb3a3beccdce24d47bc658e882f97ceb1a87ce0852a9e6db426b8fc"
            + "e667870412908f05b9768570dca927ddb05fb80f1242c5208434c83ffd8c20cb661f"
            + "b5c47b89017ecda1fa54cec5a7204d2092f57b7176fbbe3b8d0275337135a8cbf7d7"
            + "73042085d93348b6f622d19be14671fba1953fc6ba3df38a4fe317270efc3b1ed631"
            + "784bf2aaf777786f44a8b0677050f130a9b3377c5c269cbe83ded94aab71f6915c76"
            + "b307c623058020bbc498bf6f31b923454729a46286cad4eb2a1fbf7efe16c505abd4"
            + "9ad5a055ad0bd1ca405b1f7145c477f7f4903b90cd474618bb50aead90a3c88fcca7"
            + "5ebd8f1fa6274c3604c27374e4ea31973394d555442def7c222d2da4678c083771b0"
            + "8500d460906def458e1121e5d575ae8b21f2b0c6d99439ec39724f65debbbba504ec"
            + "fd9f957f8148a5d44db32cadfb6c81e931222080449f100a2f290b16a56eaa48ce43"
            + "7d6340ec0ba8519869aeff37f3dbefd7d67fb631132029fa880be3f59560d6d5b6f1"
            + "c84551d11acc02a0e2706c306936f578ac35f00440eeb593fc8efb6d387b1452e013"
            + "488bb6e0966ecd8ee0364bd16ad1df89bc1a6676b96ead983181d451ea2376a063b6"
            + "85d97e73d4d868552654690482e55f4547caafb0ea60634bc5b513216cb640b6baeb"
            + "d98d64e786b2f4972d6711b7e2995908ba43dd855f5fe4d59ee92efb87b59d120ded"
            + "c8bee364b713c32469533729ea37492890cab69099586082ce90cddff25aee364671"
            + "09f41b611ba0d4a5839e41f3a957a155d0a91eec26a5d51c651b22b259f4b4d23cc8"
            + "c3d5b8a4b1c324feb36d93d8a9a97bde22ffd8d3a934dd2154799fd34d0dc17b3e9e"
            + "45203e45257376ba800c2abe091ac424c6bebae649533603de6ccb51ed104412d739"
            + "8423a93e0301795d0074249828434d8252d3aa18cd6b428682e02051e6d2df08463d"
            + "106aaf2aa3f5528e1392d3b25bb52977b36af81bca74ec1a2a3b65cd14a8040c43f0"
            + "46d02f877aae69e2a8";

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.X_WING)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(parameters, Bytes.copyFrom(Hex.decode(PUBLIC_KEY_HEX)), 0x12345678);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey,
            SecretBytes.copyFrom(Hex.decode(PRIVATE_KEY_HEX), InsecureSecretKeyAccess.get()));

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(privateKey).makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);

    byte[] decrypted = decrypter.decrypt(Hex.decode(ciphertextHex), Hex.decode(associatedData));
    assertThat(decrypted).isEqualTo(Hex.decode(plaintext));
  }

  @Test
  public void testXWingHpkeRoundTrip_noPrefix_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);

    byte[] plaintext = "Hello World".getBytes(UTF_8);
    byte[] contextInfo = "AAD".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypter.decrypt(ciphertext, contextInfo);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void testXWingHpkeRoundTrip_tink_works() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.X_WING)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.create(parameters, Bytes.copyFrom(Hex.decode(PUBLIC_KEY_HEX)), 0x12345678);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey,
            SecretBytes.copyFrom(Hex.decode(PRIVATE_KEY_HEX), InsecureSecretKeyAccess.get()));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(privateKey).makePrimary())
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);

    byte[] plaintext = "Hello World".getBytes(UTF_8);
    byte[] contextInfo = "AAD".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypter.decrypt(ciphertext, contextInfo);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void encrypt_failsWithNullPlaintext() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    assertThrows(NullPointerException.class, () -> encrypter.encrypt(null, contextInfo));
  }

  @Test
  public void decrypt_failsWithNullCiphertext() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    assertThrows(NullPointerException.class, () -> decrypter.decrypt(null, contextInfo));
  }

  @Test
  public void decrypt_failsWithModifiedCiphertext() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    ciphertext[ciphertext.length - 1] ^= 1;

    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(ciphertext, contextInfo));
  }

  @Test
  public void decrypt_failsWithWrongContextInfo() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] wrongContextInfo = "wrongContextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    assertThrows(
        GeneralSecurityException.class, () -> decrypter.decrypt(ciphertext, wrongContextInfo));
  }

  @Test
  public void encryptDecrypt_succeedsWithNullContextInfo() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = null;

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypter.decrypt(ciphertext, contextInfo);

    assertThat(decrypted).isEqualTo(plaintext);
  }

    @Test
  public void encryptDecrypt_succeedsWithNonEmptyContextInfo() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);

    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypter.decrypt(ciphertext, contextInfo);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void flipMsbOfEncapsulatedKeyInCiphertext_fails() throws Exception {
    Assume.assumeTrue(XWingHpkeConscryptEncrypt.isSupported());

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(HPKE_NO_PREFIX_PRIVATE_KEY).withRandomId().makePrimary())
            .build();
    HybridEncrypt encrypter =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(HybridConfigurationV1.get(), HybridEncrypt.class);
    HybridDecrypt decrypter = handle.getPrimitive(HybridConfigurationV1.get(), HybridDecrypt.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);

    // Flip first byte of encapsulated key
    ciphertext[0] ^= (byte) (ciphertext[31] ^ 128);

    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(ciphertext, contextInfo));
  }

  @Test
  public void create_directRoundtrip_works() throws Exception {
    Assume.assumeFalse(Util.isAndroid());
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    // TODO(b/498579995): Remove this assume once the new version of Conscrypt is released in the
    // open-source.
    Assume.assumeTrue(hasXWingSupport());

    assertThat(XWingHpkeConscryptEncrypt.isSupported()).isTrue();

    HybridEncrypt encrypter =
        XWingHpkeConscryptEncrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY.getPublicKey());
    HybridDecrypt decrypter = XWingHpkeConscryptDecrypt.create(HPKE_NO_PREFIX_PRIVATE_KEY);

    byte[] plaintext = "Hello".getBytes(UTF_8);
    byte[] contextInfo = "context".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    byte[] decrypted = decrypter.decrypt(ciphertext, contextInfo);

    assertThat(decrypted).isEqualTo(plaintext);
  }
}
