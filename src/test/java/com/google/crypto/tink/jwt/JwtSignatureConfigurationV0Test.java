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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.internal.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.jwt.internal.JwtEcdsaProtoSerialization;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
import com.google.crypto.tink.signature.PublicKeySignWrapper;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.RsaSsaPkcs1SignKeyManager;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.RsaSsaPssSignKeyManager;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPkcs1ProtoSerialization;
import com.google.crypto.tink.signature.internal.RsaSsaPssProtoSerialization;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class JwtSignatureConfigurationV0Test {

  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
  private static final ECPoint P256_PUBLIC_POINT =
      new ECPoint(
          new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
          new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  private static final BigInteger P256_PRIVATE_VALUE =
      new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);

  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.7
  private static final ECPoint P521_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                  + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                  + "3A4",
              16),
          new BigInteger(
              "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                  + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                  + "CF5",
              16));
  private static final BigInteger P521_PRIVATE_VALUE =
      new BigInteger(
          "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
              + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
              + "538",
          16);

  // Test case from https://www.ietf.org/rfc/rfc6979.txt, A.2.6
  private static final ECPoint P384_PUBLIC_POINT =
      new ECPoint(
          new BigInteger(
              "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
              16),
          new BigInteger(
              "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
              16));
  private static final BigInteger P384_PRIVATE_VALUE =
      new BigInteger(
          "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
          16);

  private static final String CUSTOM_KID_VALUE =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

  // Public key taken from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
  static final BigInteger MODULUS =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                  + "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                  + "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                  + "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                  + "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                  + "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"));
  static final BigInteger P =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                  + "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                  + "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"));
  static final BigInteger Q =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                  + "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                  + "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"));
  static final BigInteger D =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                  + "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                  + "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                  + "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                  + "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                  + "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"));
  static final BigInteger DP =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                  + "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                  + "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"));
  static final BigInteger DQ =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                  + "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                  + "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"));
  static final BigInteger Q_INV =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                  + "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                  + "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"));

  // Test vector from Wycheproof's testvectors_v1/rsa_pkcs1_3072_test.json.
  static final BigInteger MODULUS_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "3I94gGcvDPnWNheopYvdJxoQm63aD6gm-UuKeVUmtqSagFZMyrqKlJGpNaU-3q4dm"
                  + "ntUY9ni7z7gznv_XUtsgUe1wHPC8iBRXVMdVaNmh6bePDR3XC8VGRrAp0LXNCIoy"
                  + "NkQ_mu8pDlTnEhd68vQ7g5LrjF1A7g87oEArHu0WHRny8Q3PEvaLu33xBYx5Qkit"
                  + "YD1vOgdJLIIyrzS11_P6Z91tJPf_Fyb2ZD3_Dvy7-OS_srjbz5O9EVsG13pnMdFF"
                  + "zOpELaDS2HsKSdNmGvjdSw1CxOjJ9q8CN_PZWVJmtJuhTRGYz6tspcMqVvPa_Bf_"
                  + "bwqgEN412mFpx8G-Ql5-f73FsNqpiWkW17t9QglpT6dlDWyPKq55cZNOP06dn4YW"
                  + "tdyfW4V-em6svQYTWSHaV25ommMZysugjQQ2-8dk_5AydNX7p_Hf4Sd4RNj9YOvj"
                  + "M9Rgcoa65RMQiUWy0AelQkj5L2IFDn6EJPHdYK_4axZk2dHALZDQzngJFMV2G_L"));
  static final BigInteger P_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "_sahC_xJtYoshQ6v69uZdkmpVXWgwXYxsBHLINejICMqgVua9gQNe_I9Jn5eBjBM"
                  + "M-BMhebUgUQvAQqXWLoINkpwA175npyY7rQxUFsq-2d50ckdDqL7CmXcOR557Np9"
                  + "Uv191pkjsl365EjKzoKeusprPIo8tkqBgAYUQ0iVd4wg1imxJbafQpRfZrZE84QL"
                  + "z6b842EHQlbFCGPsyiznVrSp-36ZPQ8fpIssxIW36qYUBfvvFQ51Y8IVCBF2feD5"));
  static final BigInteger Q_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "3Z7BzubYqXGxZpAsRKTwLvN6YgU7QSiKHYc9OZy8nnvTBu2QZIfaL0m8HBgJwNTY"
                  + "gQbWh5UY7ZJf62aq1f88K4NGbFVO2XuWq-9Vs7AjFPUNA4WgodikauA-j86RtBIS"
                  + "DwoQ3GgVcPpWS2hzus2Ze2FrK9dzP7cjreI7wQidoy5QlYNDbx40SLV5-yGyQGI"
                  + "NIEWNCPD5lauswKOY8KtqZ8n1vPfgMvsdZo_mmNgDJ1ma4_3zqqqxm68XY5RDGUvj"));
  static final BigInteger D_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BQEgW9F7iNDWYm3Q_siYoP1_aPjd3MMU900WfEBJW5WKh-TtYyAuasaPT09LiOPs"
                  + "egfYV1enRYRot2aq2aQPdzN4VUCLKNFA51wuazYE6okHu9f46VeMJACuZF0o4t7v"
                  + "i_cY4pzxL8y5L--YafQ67lvWrcIjhI0WnNbCfCdmZSdm_4GZOz4BWlU97O4P_cFi"
                  + "Tzn42Wtu1dlQR8FXC1n6LrPWiN1eFKzJQHuAlPGLRpQkTrGtzWVdhz9X_5r25P7E"
                  + "cL4ja687IMIECrNg11nItOYYv4vU4OxmmPG3LHFg7QUhyCtRdrYPtjUD0K4j9uL7"
                  + "emCTBbCvYhULkhrFP03omWZssB2wydi2UHUwFcG25oLmvzggTln3QJw4CMDlPyVJ"
                  + "NVQKOBqWPCwad8b5h_BqB6BXJobtIogtvILngjzsCApY1ysJ0AzB0kXPFY_0nMQF"
                  + "mdOvcZ3DAbSqf1sDYproU-naq-KE24bVxB0EARQ98rRZPvTjdHIJxSP1p_gPAtAR"));
  static final BigInteger DP_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "8b-0DNVlc5cay162WwzSv0UCIo8s7KWkXDdmEVHL_bCgooIztgD-cn_WunHp8eFe"
                  + "TVMmCWCQf-Ac4dYU6iILrMhRJUG3hmN9UfM1X9RCIq97Di7RHZRUtPcWUjSy6KYh"
                  + "iN_zye8hyhwW9wqDNhUHXKK5woZBOY_U9Y_PJlD3Uqpqdgy1hN2WnOyA4ctN_etr"
                  + "8au4BmGJK899wopeozCcis9_A56K9T8mfVF6NzfS3hqcoVj-8XH4vaHppvA7CRKx"));
  static final BigInteger DQ_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "Pjwq6NNi3JKU4txx0gUPfd_Z6lTVwwKDZq9nvhoJzeev5y4nclPELatjK_CELKaY"
                  + "9gLZk9GG4pBMZ2q5Zsb6Oq3uxNVgAyr1sOrRAljgQS5frTGFXm3cHjdC2leECzFX"
                  + "6OlGut5vxv5F5X87oKXECCXfVrx2HNptJpN1fEvTGNQUxSfLdBTjUdfEnYVk7Teb"
                  + "wAhIBs7FCAbhyGcot80rYGISpDJnv2lNZFPcyec_W3mKSaQzHSY6IiIVS12DSkNJ"));
  static final BigInteger Q_INV_3072 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "GMyXHpGG-GwUTRQM6rvJriLJTo2FdTVvtqSgM5ke8hC6-jmkzRq_qZszL96eVpVa"
                  + "8XlFmnI2pwC3_R2ICTkG9hMK58qXQtntDVxj5qnptD302LJhwS0sL5FIvAZp8WW4"
                  + "uIGHnD7VjUps1aPxGT6avSeEYJwB-5CUx8giUyrXrsKgiu6eJjCVrQQmRVy1kljH"
                  + "_Tcxyone4xgA0ZHtcklyHCUmZlDEbcv7rjBwYE0uAJkUouJpoBuvpb34u6McTztg"));

  // Test vector from Wycheproof's testvectors_v1/rsa_pkcs1_4096_test.json.
  static final BigInteger MODULUS_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "9gG-DczQSqQLEvPxka4XwfnIwLaOenfhS-JcPHkHyx0zpu9BjvQYUvMsmDkr"
                  + "xcmu2RwaFQHFA-q4mz7m9PjrLg_PxBvQNgnPao6zqm8PviMYezPbTTS2bRKK"
                  + "iroKKr9Au50T2OJVRWmlerHYxhuMrS3IhZmuDaU0bhXazhuse_aXN8IvCDvp"
                  + "tGu4seq1lXstp0AnXpbIcZW5b-EUUhWdr8_ZFs7l10mne8OQWl69OHrkRej-"
                  + "cPFumghmOXec7_v9QVV72Zrqajcaa0sWBhWhoSvGlY00vODIWty9g5L6EM7K"
                  + "UiCdVhlro9JzziKPHxERkqqS3ioDl5ihe87LTcYQDm-K6MJkPyrnaLIlXwgs"
                  + "l46VylUVVfEGCCMc-AA7v4B5af_x5RkUuajJuPRWRkW55dcF_60pZj9drj12"
                  + "ZStCLkPxPmwUkQkIBcLRJop0olEXdCfjOpqRF1w2cLkXRgCLzh_SMebk8q1w"
                  + "y0OspfB2AKbTHdApFSQ9_dlDoCFl2jZ6a35Nrh3S6Lg2kDCAeV0lhQdswcFd"
                  + "2ejS5eBHUmVpsb_TldlX65_eMl00LRRCbnHv3BiHUV5TzepYNJIfkoYp50ju"
                  + "0JesQCTivyVdcEEfhzc5SM-Oiqfv-isKtH1RZgkeGu3sYFaLFVvZwnvFXz7O"
                  + "Nfg9Y2281av0hToFHblNUEU"));
  private static final BigInteger P_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "_CG4VcWtTKK2lwUWQG9xxuee_EEm5lmHctseCC3msN3aqiopUfBBSOhuC94o"
                  + "ITt_YA-YcwgwHqzqE0Biuww932KNqav5PvHOPnWwlTpITb01VL1cBkmTPdd-"
                  + "UnVj6Q8FqAE_3ayVjDKTeOlDA7MEvl-d8f5bBDp_3ZRwCj8LHLvQUWt82UxX"
                  + "ypbZ_SqMqXOZEhjLozocI9gQ91GdH3cCq3Kv_bP4ShsqiBFuQDO8TQz8eYnG"
                  + "V-D-lOlkR2rli65reHbzbAnTKxpj-MR8lKdMku7fdfwnz_4PhFI2PkvI92U_"
                  + "PLVer2k87HDRPIdd6TWosgQ5q36T92mBxZV_xbtE2Q"));
  private static final BigInteger Q_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "-cf3SKUF0j7O-ahfgJfIz31wKO9skOIqM2URWC0sw2NuNOrTcgTb0i8UKj-x"
                  + "1fhXsDEMekM_Ua4U1GCLAbQ6qMeuZ4Nff74LnZeUiznpui06FoftuLVu5w_w"
                  + "U22rTQVR9x7Q2u6eQSRJ9fCZvMFeTvBVTcefh_7FoN6nF8cFQ5K_REYTk3QB"
                  + "u-88Ivv35zjFh3m5gWCaH5wR3W8LvpmW4nc0WeTO8kewKp_CEpasV6WxBWGC"
                  + "QxDPvezJDgZZg3DjaYcT_b4lKOxO89zKrnAe7cPlStbnr05o47Ob0ul6yRGZ"
                  + "NsZHpQNRHLKD35hM_XwH8PVqqK4xZpSO8_QbCFmTTQ"));
  private static final BigInteger D_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "BlAoIkQxyjXof4LZcwLJOEtNNBOF7NhRD035TlH6zw2_oBaUE54_AONIWdsJ"
                  + "vQh-dLLhwSKWUuc99-ScL7LdnNp_W0nYGjLpQD5Ll7bu6_226J59j78nuVKC"
                  + "_KlmjmScaCl782e83CGobfwiEyoXfkWRAktd1JrQkXdScfydfLbozYpYWPk_"
                  + "TPKAvwwbadZ15vdgq0Q_qO6N34miqF1GpSw2fCfbbR7GQ15S64bH4KsCsFVD"
                  + "hlQjzE8lNG9V4dtmdeaYMuQ6BMzHivOr1oR37Tdpirf2H6y9vNsyVS3l6J2D"
                  + "QqqfRFuK-sgb_FvAWYHqILNA6Uj3EPez7oXxi1w8WDLyM2cGxenJvY5D0gLn"
                  + "Og9id230txWXXt3TGqZDsUFFBXtJlVVt5hTFezMpe9oOBai4iCopVjvyFobO"
                  + "NMOWD5Bd5zkRmH62luB-rApjhX4olMO0YpR37L8fx26vuyzkoPAPjNtvvWFp"
                  + "45kVFGBSLPWzZdm7uVh9B9rIxDiYKt6p_yQ6hrvfEo6qDTqIhx2M3wgYVCWK"
                  + "ZR_0Im7pdJtKat0JDBWczqBrmhCATl_hUSDMY6WXLqsOQ5gN7a_zIfre6jym"
                  + "DDuhwpgLtZfqeDuAq266h_61dU_R1l18rW-Bz1LBpr_r-ademjFss2TYz0Z9"
                  + "ljcIcd8u5m7hwWlKAiOVg5E"));
  private static final BigInteger DP_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "gVSGqrCgiWv5fxPj6x9_XEkZW0nMO2J3QSo2iHmLGPRkIt9HnLlBs7VOJZZK"
                  + "PWm4l7zINVFg5YtK8p8XRd0sq7Zw9jS5wFjms1FJR_LCfeXtQk9zseHxvkoY"
                  + "iRGgMz86Zohliz7o4yZaUS5N6srcRw7jBOu1IkEjr7RhmE_oUk_gtrMNMqWf"
                  + "btLcdKlrx8v9G7ROWKcJIjXF1icuEqLIYsuMjPXRCapPscZHKHWhRGDB7VIH"
                  + "xLIrxJTHlH63ymOoyv0xNh0ADd8WotefE92RQNl5FJtIjL9ElFpbaq8TIhv0"
                  + "SR67t_yifKIOIh9Jw8N7ifzy3A4stj-Pipt6FCJQWQ"));
  private static final BigInteger DQ_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "th2E_5NKTkN7Fu4bS5_fSuEzcLU4W956VGShI8A0PfV1-eEo7535RCMNOcyc"
                  + "9dwO2yi350C2nvAkwb_uOfzVNA_66gAQFgxTXcCSDnzYG-Uz0A-lVKH8TT4C"
                  + "xGFWn158p4fxUV7fRbGWt1mITeZSw41ZNM-SUk6Ae007WQvDm8QX7kiFp2HS"
                  + "jdrc5sj9s7lh0-f9SAZN-TQKln-LeZl0OIQfSFeaR23bVQiMMI9o8rKdAcZZ"
                  + "elp8jQZihPY-N6aMOHnDKqODZnX9DrJxmIOpGURWHp3X6KprsXFX8IxI-Ob6"
                  + "5cPlortrXVgO7GyX3c2b4KSe8oOnAxrXq6jUON9OlQ"));
  private static final BigInteger Q_INV_4096 =
      new BigInteger(
          1,
          Base64.urlSafeDecode(
              "IvuOX82bdnEE5xJE21MFjBgGHhsNH2O3Pi1ZqV4qEM2HQmoz2hPCh83vgTbl"
                  + "5H6T-5swrZJiintUP0jrARqGNWqzy0gPJ-ORsBjKGH2Xrz2C4xhh7K-mY9t4"
                  + "qonDvUaOaq3vs6Q_eLwAuAFMldtU6dIaAX6PIfZxVF7d6all6jLf_0XNo3_K"
                  + "GqUTL2yO7SIr0B_tWm59Y5WAxZVXd6hlRMLEyTm9uLTEht2lMHKGGgM0NZvb"
                  + "N1hHXknZDQU5lE54z8_Y__Vbsxoc68ZbKPUeeQcBsveRIYiYTwNObpbhxSUe"
                  + "M_44-yIbznqQqGhXxfVrbKdzB8RdUpCx8Iit4IKzSQ"));

  private static void createTestKeys() {
    try {
      JwtEcdsaParameters jwtEcdsaEs256RawParameters =
          JwtEcdsaParameters.builder()
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256RawParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256RawPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs256Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256Parameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256PublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs256CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs256CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256CustomKidParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs256WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs256CustomKidParameters)
              .setPublicPoint(P256_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs256WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs256WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P256_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512RawParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512RawParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512RawPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512Parameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512PublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs512CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs512CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512CustomKidParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs512WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs512CustomKidParameters)
              .setPublicPoint(P521_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs512WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs512WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P521_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384RawParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384RawPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384RawParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384RawPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384RawPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384Parameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384PublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384Parameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setIdRequirement(123)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384PrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384PublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaParameters jwtEcdsaEs384CustomKidParameters =
          JwtEcdsaParameters.builder()
              .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
              .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
              .build();
      JwtEcdsaPublicKey jwtEcdsaEs384CustomKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384CustomKidParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid(CUSTOM_KID_VALUE)
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384CustomKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384CustomKidPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtEcdsaPublicKey jwtEcdsaEs384WrongKidPublicKey =
          JwtEcdsaPublicKey.builder()
              .setParameters(jwtEcdsaEs384CustomKidParameters)
              .setPublicPoint(P384_PUBLIC_POINT)
              .setCustomKid("wrong")
              .build();
      JwtEcdsaPrivateKey jwtEcdsaEs384WrongKidPrivateKey =
          JwtEcdsaPrivateKey.create(
              jwtEcdsaEs384WrongKidPublicKey,
              SecretBigInteger.fromBigInteger(P384_PRIVATE_VALUE, InsecureSecretKeyAccess.get()));

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Raw2048Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Raw2048PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Raw2048Parameters)
              .setModulus(MODULUS)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Raw2048PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Raw2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Kid2048Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Kid2048PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Kid2048Parameters)
              .setModulus(MODULUS)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Kid2048PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Kid2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1CustomKid2048Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1CustomKid2048PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1CustomKid2048Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1CustomKid2048PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1CustomKid2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Raw3072Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Raw3072PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Raw3072Parameters)
              .setModulus(MODULUS_3072)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Raw3072PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Raw3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Kid3072Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Kid3072PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Kid3072Parameters)
              .setModulus(MODULUS_3072)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Kid3072PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Kid3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1CustomKid3072Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1CustomKid3072PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1CustomKid3072Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS_3072)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1CustomKid3072PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1CustomKid3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Raw4096Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Raw4096PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Raw4096Parameters)
              .setModulus(MODULUS_4096)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Raw4096PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Raw4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1Kid4096Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1Kid4096PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1Kid4096Parameters)
              .setModulus(MODULUS_4096)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1Kid4096PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1Kid4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPkcs1Parameters jwtRsaSsaPkcs1CustomKid4096Parameters =
          JwtRsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
              .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
              .build();
      JwtRsaSsaPkcs1PublicKey jwtRsaSsaPkcs1CustomKid4096PublicKey =
          JwtRsaSsaPkcs1PublicKey.builder()
              .setParameters(jwtRsaSsaPkcs1CustomKid4096Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS_4096)
              .build();
      JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1CustomKid4096PrivateKey =
          JwtRsaSsaPkcs1PrivateKey.builder()
              .setPublicKey(jwtRsaSsaPkcs1CustomKid4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssRaw2048Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssRaw2048PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssRaw2048Parameters)
              .setModulus(MODULUS)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssRaw2048PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssRaw2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssKid2048Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssKid2048PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssKid2048Parameters)
              .setModulus(MODULUS)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssKid2048PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssKid2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssCustomKid2048Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(2048)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssCustomKid2048PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssCustomKid2048Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssCustomKid2048PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssCustomKid2048PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(SecretBigInteger.fromBigInteger(D, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssRaw3072Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssRaw3072PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssRaw3072Parameters)
              .setModulus(MODULUS_3072)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssRaw3072PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssRaw3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssKid3072Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssKid3072PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssKid3072Parameters)
              .setModulus(MODULUS_3072)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssKid3072PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssKid3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssCustomKid3072Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(3072)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssCustomKid3072PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssCustomKid3072Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS_3072)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssCustomKid3072PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssCustomKid3072PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_3072, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_3072, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_3072, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_3072, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_3072, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssRaw4096Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssRaw4096PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssRaw4096Parameters)
              .setModulus(MODULUS_4096)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssRaw4096PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssRaw4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssKid4096Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssKid4096PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssKid4096Parameters)
              .setModulus(MODULUS_4096)
              .setIdRequirement(123)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssKid4096PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssKid4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      JwtRsaSsaPssParameters jwtRsaSsaPssCustomKid4096Parameters =
          JwtRsaSsaPssParameters.builder()
              .setModulusSizeBits(4096)
              .setPublicExponent(JwtRsaSsaPssParameters.F4)
              .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)
              .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
              .build();
      JwtRsaSsaPssPublicKey jwtRsaSsaPssCustomKid4096PublicKey =
          JwtRsaSsaPssPublicKey.builder()
              .setParameters(jwtRsaSsaPssCustomKid4096Parameters)
              .setCustomKid(CUSTOM_KID_VALUE)
              .setModulus(MODULUS_4096)
              .build();
      JwtRsaSsaPssPrivateKey jwtRsaSsaPssCustomKid4096PrivateKey =
          JwtRsaSsaPssPrivateKey.builder()
              .setPublicKey(jwtRsaSsaPssCustomKid4096PublicKey)
              .setPrimes(
                  SecretBigInteger.fromBigInteger(P_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(Q_4096, InsecureSecretKeyAccess.get()))
              .setPrivateExponent(
                  SecretBigInteger.fromBigInteger(D_4096, InsecureSecretKeyAccess.get()))
              .setPrimeExponents(
                  SecretBigInteger.fromBigInteger(DP_4096, InsecureSecretKeyAccess.get()),
                  SecretBigInteger.fromBigInteger(DQ_4096, InsecureSecretKeyAccess.get()))
              .setCrtCoefficient(
                  SecretBigInteger.fromBigInteger(Q_INV_4096, InsecureSecretKeyAccess.get()))
              .build();

      jwtPrivateKeys =
          new JwtSignaturePrivateKey[] {
            jwtEcdsaEs256RawPrivateKey,
            jwtEcdsaEs256PrivateKey,
            jwtEcdsaEs384RawPrivateKey,
            jwtEcdsaEs384PrivateKey,
            jwtEcdsaEs512RawPrivateKey,
            jwtEcdsaEs512PrivateKey,
            jwtRsaSsaPkcs1Raw2048PrivateKey,
            jwtRsaSsaPkcs1Kid2048PrivateKey,
            jwtRsaSsaPkcs1CustomKid2048PrivateKey,
            jwtRsaSsaPkcs1Raw3072PrivateKey,
            jwtRsaSsaPkcs1Kid3072PrivateKey,
            jwtRsaSsaPkcs1CustomKid3072PrivateKey,
            jwtRsaSsaPkcs1Raw4096PrivateKey,
            jwtRsaSsaPkcs1Kid4096PrivateKey,
            jwtRsaSsaPkcs1CustomKid4096PrivateKey,
            jwtRsaSsaPssRaw2048PrivateKey,
            jwtRsaSsaPssKid2048PrivateKey,
            jwtRsaSsaPssCustomKid2048PrivateKey,
            jwtRsaSsaPssRaw3072PrivateKey,
            jwtRsaSsaPssKid3072PrivateKey,
            jwtRsaSsaPssCustomKid3072PrivateKey,
            jwtRsaSsaPssRaw4096PrivateKey,
            jwtRsaSsaPssKid4096PrivateKey,
            jwtRsaSsaPssCustomKid4096PrivateKey,
          };

      jwtPrivateKeyPairs =
          new JwtSignaturePrivateKey[][] {
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs256RawPrivateKey, jwtEcdsaEs256CustomKidPrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs384RawPrivateKey, jwtEcdsaEs384CustomKidPrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs512RawPrivateKey, jwtEcdsaEs512CustomKidPrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw2048PrivateKey, jwtRsaSsaPkcs1CustomKid2048PrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw3072PrivateKey, jwtRsaSsaPkcs1CustomKid3072PrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw4096PrivateKey, jwtRsaSsaPkcs1CustomKid4096PrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw2048PrivateKey, jwtRsaSsaPssCustomKid2048PrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw3072PrivateKey, jwtRsaSsaPssCustomKid3072PrivateKey,
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw4096PrivateKey, jwtRsaSsaPssCustomKid4096PrivateKey,
            },
          };

      jwtPrivateKeyPairsDifferentKids =
          new JwtSignaturePrivateKey[][] {
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs256CustomKidPrivateKey, jwtEcdsaEs256WrongKidPrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs384CustomKidPrivateKey, jwtEcdsaEs384WrongKidPrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtEcdsaEs512CustomKidPrivateKey, jwtEcdsaEs512WrongKidPrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw2048PrivateKey, jwtRsaSsaPkcs1Kid2048PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw3072PrivateKey, jwtRsaSsaPkcs1Kid3072PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1Raw4096PrivateKey, jwtRsaSsaPkcs1Kid4096PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1CustomKid2048PrivateKey, jwtRsaSsaPkcs1Kid2048PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1CustomKid3072PrivateKey, jwtRsaSsaPkcs1Kid3072PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPkcs1CustomKid4096PrivateKey, jwtRsaSsaPkcs1Kid4096PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw2048PrivateKey, jwtRsaSsaPssKid2048PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw3072PrivateKey, jwtRsaSsaPssKid3072PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssRaw4096PrivateKey, jwtRsaSsaPssKid4096PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssCustomKid2048PrivateKey, jwtRsaSsaPssKid2048PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssCustomKid3072PrivateKey, jwtRsaSsaPssKid3072PrivateKey
            },
            new JwtSignaturePrivateKey[] {
              jwtRsaSsaPssCustomKid4096PrivateKey, jwtRsaSsaPssKid4096PrivateKey
            },
          };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeys")
  public static JwtSignaturePrivateKey[] jwtPrivateKeys;

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeyPairs")
  public static JwtSignaturePrivateKey[][] jwtPrivateKeyPairs;

  @SuppressWarnings("NonFinalStaticField") // has to be static because of @DataPoints
  @DataPoints("jwtPrivateKeyPairsDifferentKids")
  public static JwtSignaturePrivateKey[][] jwtPrivateKeyPairsDifferentKids;

  @BeforeClass
  public static void setUp() throws Exception {
    createTestKeys();

    JwtEcdsaProtoSerialization.register();
    EcdsaProtoSerialization.register();
    JwtRsaSsaPkcs1ProtoSerialization.register();
    RsaSsaPkcs1ProtoSerialization.register();
    JwtRsaSsaPssProtoSerialization.register();
    RsaSsaPssProtoSerialization.register();
    XChaCha20Poly1305ProtoSerialization.register();

    // Needed until we replaced RegistryConfiguration with SignatureConfiguration.
    PublicKeySignWrapper.register();
    EcdsaSignKeyManager.registerPair(false);
    RsaSsaPkcs1SignKeyManager.registerPair(false);
    RsaSsaPssSignKeyManager.registerPair(false);
  }

  @Test
  public void get_works() throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    assertThat(JwtSignatureConfigurationV0.get()).isNotNull();
  }

  @Test
  public void getInFipsModeWithoutBoringCrypto_fails() throws Exception {
    assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(GeneralSecurityException.class, JwtSignatureConfigurationV0::get);
  }

  // The following test functions are inspired by
  // src/test/java/com/google/crypto/tink/jwt/JwtEcdsaSignKeyManagerTest.java.

  // This also tests that all the expected key types -- Ecdsa, RsaSsaPkcs1, and RsaSsaPss --
  // are indeed supported by the Configuration.
  @Theory
  public void getPrimitive_signVerify_works(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .allowMissingExpiration()
                .expectTypeHeader("typeHeader")
                .build());

    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  @Theory
  public void getPrimitive_signVerifyDifferentKey_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherKeysetHandle;
    if (key.equalsKey(jwtPrivateKeys[0]) || key.equalsKey(jwtPrivateKeys[1])) {
      otherKeysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(jwtPrivateKeys[2]).withFixedId(123).makePrimary())
              .build();
    } else {
      otherKeysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(jwtPrivateKeys[0]).withFixedId(123).makePrimary())
              .build();
    }
    JwtPublicKeyVerify otherVerifier =
        otherKeysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Theory
  public void getPrimitive_signVerifyHeaderModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("issuer").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Theory
  public void getPrimitive_signVerifyPayloadModification_throws(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan.
      return;
    }

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(123).makePrimary())
            .build();
    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  private static String generateSignedCompact(
      PublicKeySign rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature = Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  // Ecdsa-specific tests
  private static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.CurveType.NIST_P256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.CurveType.NIST_P384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static EcdsaParameters.HashType getEcdsaHash(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @Theory
  public void getPrimitive_signVerifyEcdsaRawDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                == JwtEcdsaParameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPrivateKey).withFixedId(123).makePrimary())
            .build();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getEcdsaHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JsonObject payload = new JsonObject();
    payload.addProperty("jid", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Normal, valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String normalSignedCompact = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // for raw keys, the validation should work even if a "kid" header is present.
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Theory
  public void getPrimitive_signVerifyEcdsaTinkDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtEcdsaPrivateKey
            && ((JwtEcdsaPrivateKey) key).getParameters().getKidStrategy()
                != JwtEcdsaParameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey = (JwtEcdsaPrivateKey) key;

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPrivateKey).withFixedId(123).makePrimary())
            .build();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(jwtEcdsaPrivateKey.getParameters()))
            .setHashType(getEcdsaHash(jwtEcdsaPrivateKey.getParameters()))
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(jwtEcdsaPrivateKey.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(jwtEcdsaPrivateKey.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    String kid = jwtEcdsaPrivateKey.getPublicKey().getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Normal, valid signed token.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    normalHeader.addProperty("kid", kid);
    String normalToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty(
        "alg", jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName());
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in the header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("kid", kid);
    headerWithBadAlg.addProperty(
        "alg",
        // "RS{256,384,512}"
        new StringBuilder(jwtEcdsaPrivateKey.getParameters().getAlgorithm().getStandardName())
            .replace(0, 1, "R")
            .toString());
    String badAlgToken = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(badAlgToken, validator));
  }

  // RsaSsaPkcs1-specific tests.
  private static RsaSsaPkcs1Parameters.HashType getRsaSsaPkcs1Hash(
      JwtRsaSsaPkcs1Parameters parameters) throws GeneralSecurityException {
    if (parameters.getModulusSizeBits() == 2048) {
      return RsaSsaPkcs1Parameters.HashType.SHA256;
    }
    if (parameters.getModulusSizeBits() == 3072) {
      return RsaSsaPkcs1Parameters.HashType.SHA384;
    }
    if (parameters.getModulusSizeBits() == 4096) {
      return RsaSsaPkcs1Parameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static String getRsaSsaPkcs1Alg(JwtRsaSsaPkcs1Parameters parameters)
      throws GeneralSecurityException {
    if (parameters.getModulusSizeBits() == 2048) {
      return "RS256";
    }
    if (parameters.getModulusSizeBits() == 3072) {
      return "RS384";
    }
    if (parameters.getModulusSizeBits() == 4096) {
      return "RS512";
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @Theory
  public void getPrimitive_signVerifyRsaSsaPkcs1DifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtRsaSsaPkcs1PrivateKey
            && ((JwtRsaSsaPkcs1PrivateKey) key).getParameters().getKidStrategy()
                == JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1PrivateKey = (JwtRsaSsaPkcs1PrivateKey) key;

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(jwtRsaSsaPkcs1PrivateKey).withFixedId(123).makePrimary())
            .build();
    RsaSsaPkcs1Parameters nonJwtParameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(getRsaSsaPkcs1Hash(jwtRsaSsaPkcs1PrivateKey.getParameters()))
            .setModulusSizeBits(jwtRsaSsaPkcs1PrivateKey.getParameters().getModulusSizeBits())
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey nonJwtPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(jwtRsaSsaPkcs1PrivateKey.getPublicKey().getModulus())
            .build();
    RsaSsaPkcs1PrivateKey nonJwtPrivateKey =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(jwtRsaSsaPkcs1PrivateKey.getPrimeP(), jwtRsaSsaPkcs1PrivateKey.getPrimeQ())
            .setPrivateExponent(jwtRsaSsaPkcs1PrivateKey.getPrivateExponent())
            .setPrimeExponents(
                jwtRsaSsaPkcs1PrivateKey.getPrimeExponentP(),
                jwtRsaSsaPkcs1PrivateKey.getPrimeExponentQ())
            .setCrtCoefficient(jwtRsaSsaPkcs1PrivateKey.getCrtCoefficient())
            .build();

    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", getRsaSsaPkcs1Alg(jwtRsaSsaPkcs1PrivateKey.getParameters()));
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    Object unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with an unknown algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS255");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "kid" in the header is valid
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty(
        "alg", getRsaSsaPkcs1Alg(jwtRsaSsaPkcs1PrivateKey.getParameters()));
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Theory
  public void getPrimitive_signVerifyRsaSsaPkcs1TinkDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(key instanceof JwtRsaSsaPkcs1PrivateKey && !key.getParameters().allowKidAbsent());
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPkcs1PrivateKey jwtRsaSsaPkcs1PrivateKey = (JwtRsaSsaPkcs1PrivateKey) key;

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(jwtRsaSsaPkcs1PrivateKey).withFixedId(123).makePrimary())
            .build();
    RsaSsaPkcs1Parameters nonJwtParameters =
        RsaSsaPkcs1Parameters.builder()
            .setHashType(getRsaSsaPkcs1Hash(jwtRsaSsaPkcs1PrivateKey.getParameters()))
            .setModulusSizeBits(jwtRsaSsaPkcs1PrivateKey.getParameters().getModulusSizeBits())
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PublicKey nonJwtPublicKey =
        RsaSsaPkcs1PublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(jwtRsaSsaPkcs1PrivateKey.getPublicKey().getModulus())
            .build();
    RsaSsaPkcs1PrivateKey nonJwtPrivateKey =
        RsaSsaPkcs1PrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(jwtRsaSsaPkcs1PrivateKey.getPrimeP(), jwtRsaSsaPkcs1PrivateKey.getPrimeQ())
            .setPrivateExponent(jwtRsaSsaPkcs1PrivateKey.getPrivateExponent())
            .setPrimeExponents(
                jwtRsaSsaPkcs1PrivateKey.getPrimeExponentP(),
                jwtRsaSsaPkcs1PrivateKey.getPrimeExponentQ())
            .setCrtCoefficient(jwtRsaSsaPkcs1PrivateKey.getCrtCoefficient())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = jwtRsaSsaPkcs1PrivateKey.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // normal, valid token
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", getRsaSsaPkcs1Alg(jwtRsaSsaPkcs1PrivateKey.getParameters()));
    normalHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty(
        "alg", getRsaSsaPkcs1Alg(jwtRsaSsaPkcs1PrivateKey.getParameters()));
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // invalid token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("alg", "PS256");
    headerWithBadAlg.addProperty("kid", kid);
    String tokenWithBadAlg = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithBadAlg, validator));

    // token with an unknown "kid" in the header is invalid
    JsonObject headerWithUnknownKid = new JsonObject();
    headerWithUnknownKid.addProperty(
        "alg", getRsaSsaPkcs1Alg(jwtRsaSsaPkcs1PrivateKey.getParameters()));
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  // RsaSsaPkcs1-specific tests.
  private static RsaSsaPssParameters.HashType getRsaSsaPssHash(JwtRsaSsaPssParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return RsaSsaPssParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return RsaSsaPssParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return RsaSsaPssParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static String getRsaSsaPssAlg(JwtRsaSsaPssParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return "PS256";
    }
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return "PS384";
    }
    if (parameters.getAlgorithm().equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return "PS512";
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  private static int saltLengthForPssAlgorithm(JwtRsaSsaPssParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return 32;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return 48;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return 64;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  @Theory
  public void getPrimitive_signVerifyRsaSsaPssDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(
        key instanceof JwtRsaSsaPssPrivateKey
            && ((JwtRsaSsaPssPrivateKey) key).getParameters().getKidStrategy()
                == JwtRsaSsaPssParameters.KidStrategy.IGNORED);
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPssPrivateKey jwtRsaSsaPssPrivateKey = (JwtRsaSsaPssPrivateKey) key;

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtRsaSsaPssPrivateKey).withFixedId(123).makePrimary())
            .build();
    RsaSsaPssParameters nonJwtParameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(getRsaSsaPssHash(jwtRsaSsaPssPrivateKey.getParameters()))
            .setMgf1HashType(getRsaSsaPssHash(jwtRsaSsaPssPrivateKey.getParameters()))
            .setSaltLengthBytes(
                saltLengthForPssAlgorithm(jwtRsaSsaPssPrivateKey.getParameters().getAlgorithm()))
            .setModulusSizeBits(jwtRsaSsaPssPrivateKey.getParameters().getModulusSizeBits())
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPublicKey nonJwtPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(jwtRsaSsaPssPrivateKey.getPublicKey().getModulus())
            .build();
    RsaSsaPssPrivateKey nonJwtPrivateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(jwtRsaSsaPssPrivateKey.getPrimeP(), jwtRsaSsaPssPrivateKey.getPrimeQ())
            .setPrivateExponent(jwtRsaSsaPssPrivateKey.getPrivateExponent())
            .setPrimeExponents(
                jwtRsaSsaPssPrivateKey.getPrimeExponentP(),
                jwtRsaSsaPssPrivateKey.getPrimeExponentQ())
            .setCrtCoefficient(jwtRsaSsaPssPrivateKey.getCrtCoefficient())
            .build();

    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", getRsaSsaPssAlg(jwtRsaSsaPssPrivateKey.getParameters()));
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    Object unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "kid" in the header is valid
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", getRsaSsaPssAlg(jwtRsaSsaPssPrivateKey.getParameters()));
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Theory
  public void getPrimitive_signVerifyRsaSsaPssTinkDifferentHeaders(
      @FromDataPoints("jwtPrivateKeys") JwtSignaturePrivateKey key) throws Exception {
    assumeTrue(key instanceof JwtRsaSsaPssPrivateKey && !key.getParameters().allowKidAbsent());
    if (TestUtil.isTsan()) {
      // creating keys is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    JwtRsaSsaPssPrivateKey jwtRsaSsaPssPrivateKey = (JwtRsaSsaPssPrivateKey) key;

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtRsaSsaPssPrivateKey).withFixedId(123).makePrimary())
            .build();
    RsaSsaPssParameters nonJwtParameters =
        RsaSsaPssParameters.builder()
            .setSigHashType(getRsaSsaPssHash(jwtRsaSsaPssPrivateKey.getParameters()))
            .setMgf1HashType(getRsaSsaPssHash(jwtRsaSsaPssPrivateKey.getParameters()))
            .setSaltLengthBytes(
                saltLengthForPssAlgorithm(jwtRsaSsaPssPrivateKey.getParameters().getAlgorithm()))
            .setModulusSizeBits(jwtRsaSsaPssPrivateKey.getParameters().getModulusSizeBits())
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPssPublicKey nonJwtPublicKey =
        RsaSsaPssPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setModulus(jwtRsaSsaPssPrivateKey.getPublicKey().getModulus())
            .build();
    RsaSsaPssPrivateKey nonJwtPrivateKey =
        RsaSsaPssPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrimes(jwtRsaSsaPssPrivateKey.getPrimeP(), jwtRsaSsaPssPrivateKey.getPrimeQ())
            .setPrivateExponent(jwtRsaSsaPssPrivateKey.getPrivateExponent())
            .setPrimeExponents(
                jwtRsaSsaPssPrivateKey.getPrimeExponentP(),
                jwtRsaSsaPssPrivateKey.getPrimeExponentQ())
            .setCrtCoefficient(jwtRsaSsaPssPrivateKey.getCrtCoefficient())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);

    JwtPublicKeyVerify verifier =
        handle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = jwtRsaSsaPssPrivateKey.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // normal, valid token
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", getRsaSsaPssAlg(jwtRsaSsaPssPrivateKey.getParameters()));
    normalHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", getRsaSsaPssAlg(jwtRsaSsaPssPrivateKey.getParameters()));
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // invalid token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("alg", "RS256");
    headerWithBadAlg.addProperty("kid", kid);
    String tokenWithBadAlg = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithBadAlg, validator));

    // token with an unknown "kid" in the header is invalid
    JsonObject headerWithUnknownKid = new JsonObject();
    headerWithUnknownKid.addProperty(
        "alg", getRsaSsaPssAlg(jwtRsaSsaPssPrivateKey.getParameters()));
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  // End of algorithm-specific tests.

  @SuppressWarnings("AvoidObjectArrays")
  @Theory
  public void getPrimitive_signVerifyWithCustomKid_works(
      @FromDataPoints("jwtPrivateKeyPairs") JwtSignaturePrivateKey[] keys) throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[0]).withRandomId().makePrimary())
            .build();
    KeysetHandle keysetHandleWithCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[1]).withFixedId(123).makePrimary())
            .build();

    JwtPublicKeySign signerWithKid =
        keysetHandleWithCustomKid.getPrimitive(
            JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    JwtPublicKeySign signerWithoutKid =
        keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo(CUSTOM_KID_VALUE);
    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid =
        keysetHandle
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify verifierWithKid =
        keysetHandleWithCustomKid
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    // Even if custom_kid is set, we don't require a "kid" in the header.
    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");

    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
  }

  @SuppressWarnings("AvoidObjectArrays")
  @Theory
  public void getPrimitive_signVerifyWithWrongCustomKid_throws(
      @FromDataPoints("jwtPrivateKeyPairsDifferentKids") JwtSignaturePrivateKey[] keys)
      throws Exception {
    if (TestUtil.isTsan()) {
      // This test takes a long time under TSan. Similar functionality is tested in the other tests.
      return;
    }

    KeysetHandle keysetHandleWithCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[0]).withFixedId(123).makePrimary())
            .build();
    KeysetHandle keysetHandleWithWrongCustomKid =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keys[1]).withFixedId(123).makePrimary())
            .build();

    JwtPublicKeySign signerWithKid =
        keysetHandleWithCustomKid.getPrimitive(
            JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        keysetHandleWithWrongCustomKid
            .getPublicKeysetHandle()
            .getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class);

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void wrongPrimitive_throws() throws Exception {
    XChaCha20Poly1305Key wrongTypeKey = XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(wrongTypeKey).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeySign.class));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), JwtPublicKeyVerify.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(JwtSignatureConfigurationV0.get(), Aead.class));
  }
}
