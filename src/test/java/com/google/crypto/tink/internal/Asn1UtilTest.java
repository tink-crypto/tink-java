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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.subtle.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Asn1Util}.
 *
 * <p>Verifies ASN.1 DER key encoding operations against hardcoded expected byte arrays and hex
 * strings.
 */
@RunWith(JUnit4.class)
@AccessesPartialKey
public final class Asn1UtilTest {

  private static final String HARDCODED_PUBLIC_KEY_HEX =
      "3082010a0282010100b7a43c3d64a2d5d9098fd8533fc84d60596f69d33b0df956f6659ea4e26127aeb0ee7ca8"
          + "2b580f36a14c4904723b5db91a9f93124a1d856af48ae8e31d5c7b05c5749654b8c390021a03eb7007"
          + "7a65c491d3e22aa26f9015c34ff128e0d3ce8cc28a9053f2d8cb0940199db5592752fcf111c8616236"
          + "78f741094ef189ece630ad2c24702c72f43dbd5f12fe3902e448b947d570fc920566270f21b1be3606"
          + "0d233e02a592f73210d998a5813f86a949a2a60d17382d02736d2b80b7b6ca62c78e91dc88229501b6"
          + "39f8bdf6fa549e64ef8eb3a535e7f697ae4f46c3c70f51a5f5fc8f2c2c6b9289576ddc2fc59f63d9dd"
          + "9f22ef8e053c5186706d6ab365b3f90203010001";

  private static final String HARDCODED_PRIVATE_KEY_HEX =
      "308204a30201000282010100b7a43c3d64a2d5d9098fd8533fc84d60596f69d33b0df956f6659ea4e26127aeb0"
          + "ee7ca82b580f36a14c4904723b5db91a9f93124a1d856af48ae8e31d5c7b05c5749654b8c390021a03"
          + "eb70077a65c491d3e22aa26f9015c34ff128e0d3ce8cc28a9053f2d8cb0940199db5592752fcf111c8"
          + "61623678f741094ef189ece630ad2c24702c72f43dbd5f12fe3902e448b947d570fc920566270f21b1"
          + "be36060d233e02a592f73210d998a5813f86a949a2a60d17382d02736d2b80b7b6ca62c78e91dc8822"
          + "9501b639f8bdf6fa549e64ef8eb3a535e7f697ae4f46c3c70f51a5f5fc8f2c2c6b9289576ddc2fc59f"
          + "63d9dd9f22ef8e053c5186706d6ab365b3f9020301000102820100191b5b2109a1399b72b337e029d8"
          + "38bbf37e47f999194ffd93b250fe39f50e77d3b8c752369ad379a493c967d2364b9a0309ce11b21057"
          + "2d4841b595576e4d637c9b73f221509b5fae2edb01760445e59a0a5de17653ca5f2f54bea3d8191d24"
          + "2174d046a9ecf9d549ee36a1948ecbc9c92ba539ab33c756068e3f3cc69e9cd9cf89080ed319ee4e8c"
          + "6eb516497c9bc6e0ec7891adc639141df42b02676bec5039ac5ce7d410d3b232a0030baa75337877de"
          + "db2ead8d7993da8c4a91bd397fc82405e6c73021fed5a264ec24d8ae32c47f6d4b72ead725fc0b5116"
          + "99e44390ad9a85e706f39fa82ca42de551295872a68ce8bf80949d4a0a9c37de97e767ac0102818100"
          + "dab9d2395e2129237cb12e0281c40715bb34f176e8143a8aba6dec738877191c6b4e641d97564af6ec"
          + "3e3c81df40fd059315d5af1f9613e6446ebaa2bc7ff68822d44bbc0097a5ef011b752a421a5313cf49"
          + "807dca4df5b3443c50af7a137fceac00c062d009b3e33727108b7cd82a879e870e71134d0847deb093"
          + "e53df2270b02818100d6efd18850cfecb0588773781972d3f4ea522983f4b9067289a67006d38204d2"
          + "604316a3d744568ec66ed1ce8879d8ace12ec1fdca12281d0a8fd3da3da07383e232491bef710b8f6a"
          + "642eebaae23218d5b46e93955f022c260aad8979db38aa2b413fca6d909e4c2c517ede61307b2db007"
          + "44af46aa87031390747fcd3c238b0281802a43135aa05479f570676fc36e3d693d0ab21d21e38fdd0b"
          + "e71fcc3b3a9800931c2cc66d6d4b702aabd50eaded6c4a3764872885b0edb7a49b7e65b382069ba50c"
          + "4dc6e069a0e39ffdafc780c5cafe586a8a0238cbf92a4b5c18e762308d49f9ae046b27ec98a35878d4"
          + "a47ebf3da9621100798ae1b6d5adc55a8b0915620fa702818002f7d2d3e811c6f9f46f02683129c5c5"
          + "870ad569ee12340596e3067f01a2b50056b5f67512beedd710e46cdf4641307dcaaa43a1868dd3a1fb"
          + "085b6b93184920141a8fa9e417928a4b74d0b50e6a0b390e926c487b72916c1ca65f191be6ac14a57e"
          + "442c3e7115ce857a269f59863add39a6100bbf951142389df10de6bea2db02818100952422fb0f42a7"
          + "251178c12b3f546c04b93bc0db4ebece444293ea9ae32fa96e7b34151ccd2704a0fc2652aa9a6eef55"
          + "d3e3f2e1d439eff6daa68291bb547dd1bbee16753add21d6105825650bc90cc780be68f8b26f85a74a"
          + "18bbf9dea2d810d21cdb23982bcbb6a3758cbdfb694dc7fefa681668394bbd1c227e52c7d2388f";

  @Test
  public void rsaSsaPkcs1PublicKeyToPkcs1Bytes_matchesExpected() throws Exception {
    RsaSsaPkcs1Parameters params =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey tinkPublicKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(params, null).getPublicKey();

    byte[] result = Asn1Util.rsaSsaPkcs1PublicKeyToPkcs1Bytes(tinkPublicKey);

    assertThat(Hex.encode(result)).isEqualTo(HARDCODED_PUBLIC_KEY_HEX);
  }

  @Test
  public void rsaSsaPssPublicKeyToPkcs1Bytes_matchesExpected() throws Exception {
    RsaSsaPssParameters params =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPublicKey tinkPublicKey =
        RsaSsaPssTestUtil.privateKeyFor2048BitParameters(params, null).getPublicKey();

    byte[] result = Asn1Util.rsaSsaPssPublicKeyToPkcs1Bytes(tinkPublicKey);

    assertThat(Hex.encode(result)).isEqualTo(HARDCODED_PUBLIC_KEY_HEX);
  }

  @Test
  public void rsaSsaPkcs1PrivateKeyToPkcs1Bytes_matchesExpected() throws Exception {
    RsaSsaPkcs1Parameters params =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey tinkPrivateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(params, null);

    byte[] result = Asn1Util.rsaSsaPkcs1PrivateKeyToPkcs1Bytes(tinkPrivateKey);

    assertThat(Hex.encode(result)).isEqualTo(HARDCODED_PRIVATE_KEY_HEX);
  }

  @Test
  public void rsaSsaPssPrivateKeyToPkcs1Bytes_matchesExpected() throws Exception {
    RsaSsaPssParameters params =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey tinkPrivateKey =
        RsaSsaPssTestUtil.privateKeyFor2048BitParameters(params, null);

    byte[] result = Asn1Util.rsaSsaPssPrivateKeyToPkcs1Bytes(tinkPrivateKey);

    assertThat(Hex.encode(result)).isEqualTo(HARDCODED_PRIVATE_KEY_HEX);
  }

  @Test
  public void createPrivateKeyInfo_matchesExpectedHardcodedOutput() {
    byte[] inputPkcs1 = Hex.decode(HARDCODED_PRIVATE_KEY_HEX);
    String expectedOutputHex =
        "308204b6300d06092a864886f70d0101010500" + HARDCODED_PRIVATE_KEY_HEX;

    byte[] result = Asn1Util.createPrivateKeyInfo(inputPkcs1);

    assertThat(Hex.encode(result)).isEqualTo(expectedOutputHex);
  }

  @Test
  public void createPkcs8RsaKeyFromPkcs1RsaKey_matchesExpectedHardcodedOutput() {
    byte[] inputPkcs1 = Hex.decode(HARDCODED_PRIVATE_KEY_HEX);
    String expectedOutputHex =
        "308204bd020100300d06092a864886f70d0101010500048204a7" + HARDCODED_PRIVATE_KEY_HEX;

    byte[] result = Asn1Util.createPkcs8RsaKeyFromPkcs1RsaKey(inputPkcs1);

    assertThat(Hex.encode(result)).isEqualTo(expectedOutputHex);
  }
}
