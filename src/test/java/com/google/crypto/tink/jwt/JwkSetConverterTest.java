// Copyright 2021 Google LLC
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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.config.GlobalTinkFlags;
import com.google.crypto.tink.internal.testing.SetTinkFlag;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for JwkSetConverter */
@RunWith(Theories.class)
public final class JwkSetConverterTest {
  @Rule public SetTinkFlag setTinkFlag = new SetTinkFlag();

  @Before
  public void setup() throws Exception {
    JwtSignatureConfig.register();
  }


  private static final String ES256_JWK_SET =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]}]}";


  private static final String ES256_JWK_SET_KID =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"],"
          + "\"kid\":\"ENgjPA\"}]}";
  private static final String ES256_JWK_SET_KID_TINK =
      "{\"primaryKeyId\":1623060913,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + "\"value\":\"EAEaIQAQzyOuoYyx748ZlCdp8hyAQ5nTrUOID7L1oGGIGdIMoCIhAFMQrStMAKkBv3ub6a+0ko"
          + "CTSreYeM9xRmbQLgS54NbhKggKBkVOZ2pQQQ==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},"
          + "\"status\":\"ENABLED\",\"keyId\":1623060913,\"outputPrefixType\":\"RAW\"}]}";


  private static final String ES384_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-384\","
          + "\"x\":\"0o71ooaChpq-J5Q7iPypL7j7xGa_geG1NDLl0EF4MjTBgKRZtok3qLb-ywkrBt5k\","
          + "\"y\":\"QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO\","
          + "\"use\":\"sig\",\"alg\":\"ES384\",\"key_ops\":[\"verify\"]}]}";

  private static final String ES512_JWK_SET =
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-521\","
          + "\"x\":\"ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_RYkcxnIWvzpFSK2JFCbV\","
          + "\"y\":\"ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58bqEnaZ0G7W9qjHa2ols2\","
          + "\"use\":\"sig\",\"alg\":\"ES512\",\"key_ops\":[\"verify\"]}]}";

  //
  private static final String RS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2"
          + "GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN"
          + "6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR"
          + "1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDG"
          + "W-zXzw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";


  private static final String RS256_JWK_SET_KID =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2"
          + "GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN"
          + "6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR"
          + "1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDG"
          + "W-zXzw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"],"
          + "\"kid\":\"HL1QoQ\"}]}";
  private static final String RS256_JWK_SET_KID_TINK =
      "{\"primaryKeyId\":1204986267,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey\","
          + "\"value\":\"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwf"
          + "GMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5hZ6ifUsv8W8mSHKlsVMmvOf"
          + "C2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fF"
          + "q88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UFjj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyD"
          + "G90ABjggQqDGW+zXzyIDAQABKggKBkhMMVFvUQ==\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},"
          + "\"status\":\"ENABLED\",\"keyId\":1204986267,\"outputPrefixType\":\"RAW\"}]}";


  private static final String RS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"nlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj_mvHXAbacrngt9fzi0iv_W"
          + "Q57jUmtO1b_wLt5LYk9APsBYjywDCIe-u9UouikP7c3SBqjjQijZ50jgYbMY6cL7s2Gx5lI1vlGX3ZExLVYbNo"
          + "I9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH_KzVacTq2_pVXKVH_9_EQzcLB0oYUljZ4vYQ4HCAcwnUZb"
          + "irsRwA0350Dz0Mlj-3-9sSAF8FPA-F_wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7-bxH9p28huJSU96P4WdG5P"
          + "YVwI1VEYwGipkUIpMWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL9h-aBoxruY-m"
          + "U49kAHzzeAntn8C-vIrxN-X6N2EU9N8t9BF-mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXBRrbJyxkIVuqv"
          + "ACP5\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS384\",\"key_ops\":[\"verify\"]}]}";


  private static final String RS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"kKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbgEoQ3XWOgtNvi7QeKLE4GjQ"
          + "a5bY0xdRnu8nKjFcsvH-eu1sV8oVoZ984J5mT1mhwU6nt26p4xKyeapMhzYYNvKudQjQJ8SbpVOFpEiJ7j0ECM"
          + "Ud4Q8mCUqWsrXYE8-1CcHjprsIxdot-haCARc72RBj9cLuBIhJNzlFXNmsYh8yoSiEYr_auRvg_kIlNlnlOK_r"
          + "JM_jMXbB6FuWdePrtqZ-ce2TVyARqjZJ0G0vZcPuvOhgS4LM7_Aeal84ZhIcHladSo_g8pK1eUhnRqRXJpsltw"
          + "ux-1XVJeg2a0FQ0BN3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI-vumSy9dmY4UrgAG37N8Xj5_NeqBT51L3qE6tk2"
          + "ZLoO7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4QyQufK8k8UPiB"
          + "bWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgCK4KzPG7PwV120r6IVGfl"
          + "fpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyXZWCyWKcvTFsGrr1oECwDOmW-nUIHGklr"
          + "9Q0\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS512\",\"key_ops\":[\"verify\"]}]}";



  private static final String PS256_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7"
          + "-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZ"
          + "WBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWD"
          + "S_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBX"
          + "LMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2S"
          + "jSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrE"
          + "I2ad\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS256\",\"key_ops\":[\"verify\"]}]}";


  private static final String PS256_JWK_SET_KID =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7"
          + "-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZ"
          + "WBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWD"
          + "S_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBX"
          + "LMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2S"
          + "jSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrE"
          + "I2ad\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS256\",\"key_ops\":[\"verify\"],"
          + "\"kid\":\"Wes4wg\"}]}";
  private static final String PS256_JWK_SET_KID_TINK =
      "{\"primaryKeyId\":1004877962,\"key\":[{\"keyData\":{"
          + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey\","
          + "\"value\":\"EAEagQMAj7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d+Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1"
          + "TMmksY2Ugf/7+Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz+9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed+TLIlgvw"
          + "uSTF4B5d6QkZWBymq7My6vV+epzWnoLpVDzCHh+c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDg"
          + "wQ63rVCo2eWDS/BYK4rG22luSTDVfQVHU1NXlwXEnb/eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy"
          + "3XiSeCGtghBXLMf/ge113Q9WDJ+RN1Xa4vgHJCO0+VO+cAugVkiu9UgsPP8o/r7tA2aP/Ps8EHYa1IaZg75vnr"
          + "MZPvsTH7WG2SjSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX/PN6DLKoK2PaT0I+iLK9mRi1Z4OjFbl9KA"
          + "ZXXElhAQTzrEI2adIgMBAAEqCAoGV2VzNHdn\","
          + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},"
          + "\"status\":\"ENABLED\",\"keyId\":1004877962,\"outputPrefixType\":\"RAW\"}]}";



  private static final String PS384_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"v6a0OergWYmY1k6l6vx6Of5-RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25ehZ5LNDIiGjhE3v2--D7QE"
          + "jnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4kXypVhytjwRdiP61vG0C_eL0x-LijtM_XV"
          + "ee1Y-5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6JzLbWfDRWoqbCXKYivnw-CSE38ddW1XsrAT76E2Vf-womuw"
          + "yBbkjLaiWvNxNFBTap2IaBLKAni6x7pqYCeu1n9eMUi41oz9QM8xfOvpH-wubc2PjwyTsb1FDTLnhV36tQLTVG"
          + "dQdCDMF2Z8Agrnio3n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp_lQrsuWqe4CVJjFE1H4BxcU7L0j"
          + "8755kGJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0-niEwX_L8jqW4YMbxrGdAf"
          + "kTnP\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS384\",\"key_ops\":[\"verify\"]}]}";



  private static final String PS512_JWK_SET =
      "{\"keys\":[{\"kty\":\"RSA\","
          + "\"n\":\"nOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0StSIB7EQP4ciHa-vr59sOgM"
          + "FMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4jbScDrwNn1sQ8rkgSNczvQNpV1MtBhS_CC"
          + "1PxVF88JaejG2zr-unoFlw7xnqxBWMzNrMHZHwqga2vL3inSbvA_RGQjnE2DzQSwZkXthGSwYBjOYbGawMN4on"
          + "kAx_myHMyTg_TLAqG9GUyB0DVelvVoGZG_QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG8v1t7PveN-ST"
          + "IdTE2D548K-GDOvsvrO4ZhofS_iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUgN_iwjupk6u1S"
          + "vt-RWNJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb-ooZ6K5-hx3Rld7wXktjYIZzHqUr39P5yTw28"
          + "b8Y2dPFWR4vwr2_0zBxcDmTRRtQ7vPOtZPD0_LVIXkgbBiLILpycnucWt9Lq9Hc62KFiTQOAuuOxz7ObBegXjn"
          + "FupiZZ9PyzO5WgT9lRpH7U7tzGLAjV-AUpjH6HA1o6bRLKOHFBPS-I9IqAYb_RpF6M_6hCmC2Rz64yYzR3y4vH"
          + "KGM\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"PS512\",\"key_ops\":[\"verify\"]}]}";

  private static final String P256_PUBLIC_KEYSET_SMALL_COORDINATES =
      "{\"primaryKeyId\":2124611562,\"key\":[{\"keyData\":{\"typeUrl\":"
          + " \"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\""
          + " ,\"value\":\"EAEaH2lFjtbwLgtzRDh7dV9sYmW4IWl3ZKA+WghvrQPiCNoiIEJ8pQXMy"
          + " A/JywaGWT+IHmWxuVYWqdxkPsUSHLhSQm51\",\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"}"
          + " ,\"status\":\"ENABLED\",\"keyId\":2124611562,\"outputPrefixType\":\"TINK\"}]}";
  private static final String P384_PUBLIC_KEYSET_SMALL_COORDINATES =
      "{\"primaryKeyId\":4159170178,\"key\":[{\"keyData\":{"
          + " \"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + " \"value\":\"EAIaL/bm1+e6X7gat+MJK3e65BGlZzKIf6I1q0Ro8zAKeyryUxgvZl8Ww/NlcVN2XJhEI"
          + " jA3b73hm8eDfSEEUAAaJbrLZFOFGnSdTWng116r+hOvszYiov+WrsTyIgnL/9aRdN8=\","
          + " \"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},\"status\":\"ENABLED\","
          + " \"keyId\":4159170178,\"outputPrefixType\":\"TINK\"}]}";
  private static final String P521_PUBLIC_KEYSET_SMALL_COORDINATES =
      "{\"primaryKeyId\":1286030637,\"key\":[{\"keyData\":{"
          + " \"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
          + " \"value\":\"EAMaQUgdEssWf+tdFT3vSoy/OAotV501af+XQ6JSXDjnOPCzZnFh8fYwrJ8Yu8XYF3"
          + " 3IeHBdAIKyicKuW884JkjYR1qJIkH2OWoa4SOmk0FtpeRBZHPbs7U8SMFXVkaV+HZtjmfl11QGiQU9hqU"
          + " hoW9ock2K0xg6wdcWBe67YTVFdQbThFmtCg==\",\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},"
          + " \"status\":\"ENABLED\",\"keyId\":1286030637,\"outputPrefixType\":\"TINK\"}]}";




  private static final String JWK_SET_WITH_TWO_KEYS =
      "{\"keys\":[{"
          + "\"kty\":\"EC\","
          + "\"crv\":\"P-256\","
          + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
          + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
          + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]},"
          + "{\"kty\":\"RSA\","
          + "\"n\":\"kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2"
          + "GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN"
          + "6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR"
          + "1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDG"
          + "W-zXzw\","
          + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";

  private static void assertEqualJwkSets(String jwkSet1, String jwkSet2) throws Exception {
    // Consider these strings equal, if their equal after parsing them.
    // The keys may have any order.
    JsonObject parsedjwkSet1 = JsonParser.parseString(jwkSet1).getAsJsonObject();
    JsonObject parsedjwkSet2 = JsonParser.parseString(jwkSet2).getAsJsonObject();
    JsonArray keys1 = parsedjwkSet1.remove("keys").getAsJsonArray();
    JsonArray keys2 = parsedjwkSet2.remove("keys").getAsJsonArray();
    assertThat(keys1).containsExactlyElementsIn(keys2);
    assertThat(parsedjwkSet1).isEqualTo(parsedjwkSet2);
  }

  @Test
  public void assertEqualJwkSets_equal() throws Exception {
    // Whitespace, order of object properties, and order of keys is ignored.
    assertEqualJwkSets(
        "{\"keys\":[{\"kty\": \"EC\"},     {\"e\":\"f\",\"kty\": \"RSA\"}]}",
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"f\"}, {\"kty\":\"EC\"}]}");
  }

  @Test
  public void assertEqualJwkSets_notEequal() throws Exception {
    // Order of arrays (except "keys" array) is not ignored.
    assertThrows(
        AssertionError.class,
        () ->
            assertEqualJwkSets(
                "{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"b\",\"c\"]}]}",
                "{\"keys\":[{\"kty\":\"EC\",\"key_ops\":[\"c\",\"b\"]}]}"));
  }

  private static String convertToJwkSet(KeysetHandle handle) throws Exception {
    return JwkSetConverter.fromPublicKeysetHandle(handle);
  }

  private static KeysetHandle createEs256Keyset() throws Exception {
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1, Base64.urlSafeDecode("EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA")),
                    new BigInteger(
                        1, Base64.urlSafeDecode("UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(282600252).makePrimary())
        .build();
  }

  private static KeysetHandle createEs384Keyset() throws Exception {
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "0o71ooaChpq-J5Q7iPypL7j7xGa_geG1NDLl0EF4MjTBgKRZtok3qLb-ywkrBt5k")),
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(456087424).makePrimary())
        .build();
  }

  private static KeysetHandle createEs512Keyset() throws Exception {
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_RYkcxnIWvzpFSK2JFCbV")),
                    new BigInteger(
                        1,
                        Base64.urlSafeDecode(
                            "ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58bqEnaZ0G7W9qjHa2ols2"))))
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1570200439).makePrimary())
        .build();
  }

  private static KeysetHandle createEs256KeysetTink() throws Exception {
    JwtEcdsaPublicKey key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1, Base64.urlSafeDecode("EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA")),
                    new BigInteger(
                        1, Base64.urlSafeDecode("UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE"))))
            .setIdRequirement(282600252)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(282600252).makePrimary())
        .build();
  }

  private static KeysetHandle createRs256Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW-zXzw"));
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(482168993).makePrimary())
        .build();
  }

  private static KeysetHandle createRs384Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "nlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj_mvHXAbacrngt9fzi0iv_WQ57jUmtO1b_wLt5LYk9APsBYjywDCIe-u9UouikP7c3SBqjjQijZ50jgYbMY6cL7s2Gx5lI1vlGX3ZExLVYbNoI9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH_KzVacTq2_pVXKVH_9_EQzcLB0oYUljZ4vYQ4HCAcwnUZbirsRwA0350Dz0Mlj-3-9sSAF8FPA-F_wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7-bxH9p28huJSU96P4WdG5PYVwI1VEYwGipkUIpMWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL9h-aBoxruY-mU49kAHzzeAntn8C-vIrxN-X6N2EU9N8t9BF-mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXBRrbJyxkIVuqvACP5"));
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(333504275).makePrimary())
        .build();
  }

  private static KeysetHandle createRs512Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbgEoQ3XWOgtNvi7QeKLE4GjQa5bY0xdRnu8nKjFcsvH-eu1sV8oVoZ984J5mT1mhwU6nt26p4xKyeapMhzYYNvKudQjQJ8SbpVOFpEiJ7j0ECMUd4Q8mCUqWsrXYE8-1CcHjprsIxdot-haCARc72RBj9cLuBIhJNzlFXNmsYh8yoSiEYr_auRvg_kIlNlnlOK_rJM_jMXbB6FuWdePrtqZ-ce2TVyARqjZJ0G0vZcPuvOhgS4LM7_Aeal84ZhIcHladSo_g8pK1eUhnRqRXJpsltwux-1XVJeg2a0FQ0BN3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI-vumSy9dmY4UrgAG37N8Xj5_NeqBT51L3qE6tk2ZLoO7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4QyQufK8k8UPiBbWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgCK4KzPG7PwV120r6IVGflfpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyXZWCyWKcvTFsGrr1oECwDOmW-nUIHGklr9Q0"));
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(705596479).makePrimary())
        .build();
  }

  private static KeysetHandle createRs256KeysetTink() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW-zXzw"));
    JwtRsaSsaPkcs1PublicKey key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build())
            .setModulus(modulus)
            .setIdRequirement(482168993)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(482168993).makePrimary())
        .build();
  }

  private static KeysetHandle createPs256Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZWBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWDS_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBXLMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2SjSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrEI2ad"));
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1508587714).makePrimary())
        .build();
  }

  private static KeysetHandle createPs384Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "v6a0OergWYmY1k6l6vx6Of5-RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25ehZ5LNDIiGjhE3v2--D7QEjnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4kXypVhytjwRdiP61vG0C_eL0x-LijtM_XVee1Y-5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6JzLbWfDRWoqbCXKYivnw-CSE38ddW1XsrAT76E2Vf-womuwyBbkjLaiWvNxNFBTap2IaBLKAni6x7pqYCeu1n9eMUi41oz9QM8xfOvpH-wubc2PjwyTsb1FDTLnhV36tQLTVGdQdCDMF2Z8Agrnio3n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp_lQrsuWqe4CVJjFE1H4BxcU7L0j8755kGJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0-niEwX_L8jqW4YMbxrGdAfkTnP"));
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1042230435).makePrimary())
        .build();
  }

  private static KeysetHandle createPs512Keyset() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "nOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0StSIB7EQP4ciHa-vr59sOgMFMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4jbScDrwNn1sQ8rkgSNczvQNpV1MtBhS_CC1PxVF88JaejG2zr-unoFlw7xnqxBWMzNrMHZHwqga2vL3inSbvA_RGQjnE2DzQSwZkXthGSwYBjOYbGawMN4onkAx_myHMyTg_TLAqG9GUyB0DVelvVoGZG_QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG8v1t7PveN-STIdTE2D548K-GDOvsvrO4ZhofS_iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUgN_iwjupk6u1Svt-RWNJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb-ooZ6K5-hx3Rld7wXktjYIZzHqUr39P5yTw28b8Y2dPFWR4vwr2_0zBxcDmTRRtQ7vPOtZPD0_LVIXkgbBiLILpycnucWt9Lq9Hc62KFiTQOAuuOxz7ObBegXjnFupiZZ9PyzO5WgT9lRpH7U7tzGLAjV-AUpjH6HA1o6bRLKOHFBPS-I9IqAYb_RpF6M_6hCmC2Rz64yYzR3y4vHKGM"));
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(257081135).makePrimary())
        .build();
  }

  private static KeysetHandle createPs256KeysetTink() throws Exception {
    BigInteger modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "j7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d-Cp8biRX9wbmLJRMUvoO2j7Sp9Szx1TMmksY2Ugf_7-Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz-9fhGjM6E6sdSOUzjM6nsPulKqOQ8Aed-TLIlgvwuSTF4B5d6QkZWBymq7My6vV-epzWnoLpVDzCHh-c35r81Pyrj6tiTPQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWDS_BYK4rG22luSTDVfQVHU1NXlwXEnb_eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBXLMf_ge113Q9WDJ-RN1Xa4vgHJCO0-VO-cAugVkiu9UgsPP8o_r7tA2aP_Ps8EHYa1IaZg75vnrMZPvsTH7WG2SjSgW9GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX_PN6DLKoK2PaT0I-iLK9mRi1Z4OjFbl9KAZXXElhAQTzrEI2ad"));
    JwtRsaSsaPssPublicKey key =
        JwtRsaSsaPssPublicKey.builder()
            .setParameters(
                JwtRsaSsaPssParameters.builder()
                    .setModulusSizeBits(modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                    .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build())
            .setModulus(modulus)
            .setIdRequirement(1508587714)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(key).withFixedId(1508587714).makePrimary())
        .build();
  }

  private static KeysetHandle createPrivatekeyKeyset() throws Exception {
    String privatekeyKeyset =
        "{\"primaryKeyId\":152493399,\"key\":[{\"keyData\":{"
            + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey\","
            + "\"value\":\"EkYQARogaHkaakArEB51RyZ236S5x3BxaNTFycWuXIGZF8adZ2UiIFlZT7MFogZ8ARbS1URIAP"
            + "cpw8A0g2uwAHRkBqGUiCU2GiBI4jtU/59Zajohgeezi2BXB13O8IJh8V3b0itq5zyy5Q==\","
            + "\"keyMaterialType\":\"ASYMMETRIC_PRIVATE\""
            + "},\"status\":\"ENABLED\",\"keyId\":152493399,\"outputPrefixType\":\"RAW\"}]}";
    return TinkJsonProtoKeysetFormat.parseKeyset(privatekeyKeyset, InsecureSecretKeyAccess.get());
  }

  private static KeysetHandle createKeysetWithTwoKeys() throws Exception {
    JwtEcdsaPublicKey es256Key =
        JwtEcdsaPublicKey.builder()
            .setParameters(
                JwtEcdsaParameters.builder()
                    .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                    .build())
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        1, Base64.urlSafeDecode("EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA")),
                    new BigInteger(
                        1, Base64.urlSafeDecode("UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE"))))
            .build();
    BigInteger rs256Modulus =
        new BigInteger(
            1,
            Base64.urlSafeDecode(
                "kspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2JLaIsnwpwfGMClfe_alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI-5hZ6ifUsv8W8mSHKlsVMmvOfC2P5-l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B_n7nfiWw9YN5--pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb_Q1UFjj_F3C77NCNQ344ZcAEI42HY-uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW-zXzw"));
    JwtRsaSsaPkcs1PublicKey rs256Key =
        JwtRsaSsaPkcs1PublicKey.builder()
            .setParameters(
                JwtRsaSsaPkcs1Parameters.builder()
                    .setModulusSizeBits(rs256Modulus.bitLength())
                    .setPublicExponent(new BigInteger(1, Base64.urlSafeDecode("AQAB")))
                    .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                    .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                    .build())
            .setModulus(rs256Modulus)
            .build();
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(es256Key).withFixedId(282600252).makePrimary())
        .addEntry(KeysetHandle.importKey(rs256Key).withFixedId(482168993))
        .build();
  }

  private static byte[] getCoordinate(JsonObject jwkSet, String coordinate) throws Exception {
    return Base64.urlSafeDecode(
        jwkSet.get("keys").getAsJsonArray().get(0).getAsJsonObject().get(coordinate).getAsString());
  }

  @Test
  public void convertEcdsaKeysets_encodesFixedSizeCordinates() throws Exception {
    JsonObject jwkSet =
        JsonParser.parseString(
                convertToJwkSet(
                    TinkJsonProtoKeysetFormat.parseKeyset(
                        P256_PUBLIC_KEYSET_SMALL_COORDINATES, InsecureSecretKeyAccess.get())))
            .getAsJsonObject();
    assertThat(getCoordinate(jwkSet, "x")).hasLength(32);
    assertThat(getCoordinate(jwkSet, "y")).hasLength(32);
    jwkSet =
        JsonParser.parseString(
                convertToJwkSet(
                    TinkJsonProtoKeysetFormat.parseKeyset(
                        P384_PUBLIC_KEYSET_SMALL_COORDINATES, InsecureSecretKeyAccess.get())))
            .getAsJsonObject();
    assertThat(getCoordinate(jwkSet, "x")).hasLength(48);
    assertThat(getCoordinate(jwkSet, "y")).hasLength(48);
    jwkSet =
        JsonParser.parseString(
                convertToJwkSet(
                    TinkJsonProtoKeysetFormat.parseKeyset(
                        P521_PUBLIC_KEYSET_SMALL_COORDINATES, InsecureSecretKeyAccess.get())))
            .getAsJsonObject();
    assertThat(getCoordinate(jwkSet, "x")).hasLength(66);
    assertThat(getCoordinate(jwkSet, "y")).hasLength(66);
  }

  @Test
  public void convertEcdsaKeysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(createEs256Keyset()), ES256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createEs384Keyset()), ES384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createEs512Keyset()), ES512_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createEs256KeysetTink()), ES256_JWK_SET_KID);
  }

  @Test
  public void convertRsaSsaPkcs1Keysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(createRs256Keyset()), RS256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createRs384Keyset()), RS384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createRs512Keyset()), RS512_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createRs256KeysetTink()), RS256_JWK_SET_KID);
  }

  @Test
  public void convertRsaSsaPssKeysets_success() throws Exception {
    assertEqualJwkSets(convertToJwkSet(createPs256Keyset()), PS256_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createPs384Keyset()), PS384_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createPs512Keyset()), PS512_JWK_SET);
    assertEqualJwkSets(convertToJwkSet(createPs256KeysetTink()), PS256_JWK_SET_KID);
  }

  @Test
  public void toPublicKeysetHandlefromPublicKeysetHandle_success() throws Exception {
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(ES256_JWK_SET)),
        ES256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(ES384_JWK_SET)),
        ES384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(ES512_JWK_SET)),
        ES512_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(RS256_JWK_SET)),
        RS256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(RS384_JWK_SET)),
        RS384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(RS512_JWK_SET)),
        RS512_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(PS256_JWK_SET)),
        PS256_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(PS384_JWK_SET)),
        PS384_JWK_SET);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(JwkSetConverter.toPublicKeysetHandle(PS512_JWK_SET)),
        PS512_JWK_SET);
  }

  @Test
  public void toPublicKeysetHandleWithValidKid_fromPublicKeysetHandle_sameJwkSet()
      throws Exception {
    // When the kid can be decoded into a key ID, the output prefix type of the key will be TINK,
    // and the same kid value will be generated again when converted to JWK Set.
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(ES256_JWK_SET_KID)),
        ES256_JWK_SET_KID);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(RS256_JWK_SET_KID)),
        RS256_JWK_SET_KID);
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(PS256_JWK_SET_KID)),
        PS256_JWK_SET_KID);
  }

  @Test
  public void jwkEs256WithKid_isImportedAsRaw() throws Exception {
    KeysetHandle converted = JwkSetConverter.toPublicKeysetHandle(ES256_JWK_SET_KID);
    KeysetHandle expected =
        TinkJsonProtoKeysetFormat.parseKeyset(
            ES256_JWK_SET_KID_TINK, InsecureSecretKeyAccess.get());
    // The KeyID is picked at random, hence we just compare the keys.
    assertTrue(converted.getAt(0).getKey().equalsKey(expected.getAt(0).getKey()));
  }

  @Test
  public void jwkRs256WithKid_isImportedAsRaw() throws Exception {
    KeysetHandle converted = JwkSetConverter.toPublicKeysetHandle(RS256_JWK_SET_KID);
    KeysetHandle expected =
        TinkJsonProtoKeysetFormat.parseKeyset(
            RS256_JWK_SET_KID_TINK, InsecureSecretKeyAccess.get());
    // The KeyID is picked at random, hence we just compare the keys.
    assertTrue(converted.getAt(0).getKey().equalsKey(expected.getAt(0).getKey()));
  }

  @Test
  public void jwkPs256WithKid_isImportedAsRaw() throws Exception {
    KeysetHandle converted = JwkSetConverter.toPublicKeysetHandle(PS256_JWK_SET_KID);
    KeysetHandle expected =
        TinkJsonProtoKeysetFormat.parseKeyset(
            PS256_JWK_SET_KID_TINK, InsecureSecretKeyAccess.get());
    // The KeyID is picked at random, hence we just compare the keys.
    assertTrue(converted.getAt(0).getKey().equalsKey(expected.getAt(0).getKey()));
  }

  @Test
  public void jwkWithEmptyKid_kidIsPreserved() throws Exception {
    String esWithEmptyKid = ES256_JWK_SET_KID.replace("\"ENgjPA\"", "\"\"");
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(esWithEmptyKid)),
        esWithEmptyKid);
    String rsWithEmptyKid = RS256_JWK_SET_KID.replace("\"HL1QoQ\"", "\"\"");
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(rsWithEmptyKid)),
        rsWithEmptyKid);
    String psWithEmptyKid = PS256_JWK_SET_KID.replace("\"Wes4wg\"", "\"\"");
    assertEqualJwkSets(
        JwkSetConverter.fromPublicKeysetHandle(
            JwkSetConverter.toPublicKeysetHandle(psWithEmptyKid)),
        psWithEmptyKid);
  }

  @Test
  public void toPublicKeysetHandleSetsKeyIdsAndPrimaryKeyId() throws Exception {
    KeysetHandle handle = JwkSetConverter.toPublicKeysetHandle(JWK_SET_WITH_TWO_KEYS);
    assertThat(handle.size()).isEqualTo(2);
    assertThat(handle.getAt(0).getKey()).isInstanceOf(JwtEcdsaPublicKey.class);
    assertThat(handle.getAt(1).getKey()).isInstanceOf(JwtRsaSsaPkcs1PublicKey.class);
  }

  @DataPoints("templatesNames")
  public static final String[] TEMPLATE_NAMES =
      new String[] {
        "JWT_ES256",
        "JWT_ES384",
        "JWT_ES512",
        "JWT_ES256_RAW",
        "JWT_RS256_2048_F4",
        "JWT_RS256_3072_F4",
        "JWT_RS384_3072_F4",
        "JWT_RS512_4096_F4",
        "JWT_RS256_2048_F4_RAW",
        "JWT_PS256_2048_F4",
        "JWT_PS256_3072_F4",
        "JWT_PS384_3072_F4",
        "JWT_PS512_4096_F4",
        "JWT_PS256_2048_F4_RAW",
      };

  @Theory
  public void convertTinkToJwksTokenVerification_success(
      @FromDataPoints("templatesNames") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));

    String jwksString =
        JwkSetConverter.fromPublicKeysetHandle(keysetHandle.getPublicKeysetHandle());

    KeysetHandle publicKeysetHandle = JwkSetConverter.toPublicKeysetHandle(jwksString);

    JwtPublicKeySign signer =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        publicKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Test
  public void keysetWithTwoKeys_fromPublicKeysetHandleSuccess() throws Exception {
    assertEqualJwkSets(convertToJwkSet(createKeysetWithTwoKeys()), JWK_SET_WITH_TWO_KEYS);
  }

  @Test
  public void primaryKeyIdMissing_fromPublicKeysetHandleSuccess() throws Exception {
    String es256Keyset =
        "{\"primaryKeyId\":282600252,\"key\":[{\"keyData\":{"
            + "\"typeUrl\":\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\","
            + "\"value\":\"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m+mvtJKAk0"
            + "q3mHjPcUZm0C4EueDW4Q==\",\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\""
            + "},\"status\":\"ENABLED\",\"keyId\":282600252,\"outputPrefixType\":\"RAW\"}]}";
    String keyset = es256Keyset.replace("\"primaryKeyId\":282600252,", "");
    assertThrows(
        GeneralSecurityException.class,
        () ->
            convertToJwkSet(
                TinkJsonProtoKeysetFormat.parseKeyset(keyset, InsecureSecretKeyAccess.get())));
  }


  @Test
  public void privateKey_fromPublicKeysetHandleFails() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> convertToJwkSet(createPrivatekeyKeyset()));
  }

  @Test
  public void fromPublicKeysetHandle_throwsOnInvalidKeysetHandle() throws Exception {
    setTinkFlag.untilTheEndOfThisTest(GlobalTinkFlags.validateKeysetsOnParsing, false);
    Keyset keyset =
        Keyset.newBuilder()
            .setPrimaryKeyId(1)
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyId(1)
                    // Keysets with unknown status are not parsed properly and will throw unchecked
                    // at getAt()
                    .setStatus(KeyStatusType.UNKNOWN_STATUS)
                    .setKeyData(
                        KeyData.newBuilder()
                            .setTypeUrl("somenonexistenttypeurl")
                            .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
                            .setValue(ByteString.EMPTY)))
            .build();
    KeysetHandle handle = TinkProtoKeysetFormat.parseKeysetWithoutSecret(keyset.toByteArray());
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.fromPublicKeysetHandle(handle));
  }

  @Test
  public void ecdsaWithoutUseAndKeyOps_toPublicKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"alg\":\"ES256\""
            + "}]}";
    // ignore returned value, we only test that it worked.
    Object unused = JwkSetConverter.toPublicKeysetHandle(jwksString);
  }

  @Test
  public void ecdsaPrivateKey_fails() throws Exception {
    // Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
            + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
            + "\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","
            + "\"alg\":\"ES256\""
            + "}]}";
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithUnknownField_toPublicKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"alg\":\"ES256\","
            + "\"unknown\":1234,"
            + "\"use\":\"sig\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    // ignore returned value, we only test that it worked.
    Object unused = JwkSetConverter.toPublicKeysetHandle(jwksString);
  }

  @Test
  public void ecdsaWithoutAlg_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithoutKty_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithoutCrv_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsa_pointNotOnCurve_getPrimitiveFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"AAAwOQ\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithInvalidKty_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"RSA\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithInvalidCrv_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-384\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithInvalidUse_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"invalid\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"verify\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithInvalidKeyOps_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":[\"invalid\"]"
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void ecdsaWithStringKeyOps_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{"
            + "\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY\","
            + "\"y\":\"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI\","
            + "\"use\":\"sig\","
            + "\"alg\":\"ES256\","
            + "\"key_ops\":\"verify\""
            + "}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void rsaWithoutUseAndKeyOps_toPublicKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"alg\":\"RS256\"}]}";
    // ignore returned value, we only test that it worked.
    Object unused = JwkSetConverter.toPublicKeysetHandle(jwksString);

    String psJwksString = jwksString.replace("RS256", "PS256");
    // ignore returned value, we only test that it worked.
    unused = JwkSetConverter.toPublicKeysetHandle(psJwksString);
  }

  @Test
  public void rsaWithUnknownField_toPublicKeysetHandleSuccess() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"unknown\":1234,"
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    // ignore returned value, we only test that it worked.
    Object unused = JwkSetConverter.toPublicKeysetHandle(jwksString);

    String psJwksString = jwksString.replace("RS256", "PS256");
    // ignore returned value, we only test that it worked.
    unused = JwkSetConverter.toPublicKeysetHandle(psJwksString);
  }

  @Test
  public void rsaPrivateKey_fails() throws Exception {
    // Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    String jwksString =
        "{\"keys\":["
            + "{\"kty\":\"RSA\","
            + "\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
            + "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst"
            + "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
            + "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
            + "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"
            + "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
            + "\"e\":\"AQAB\","
            + "\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9"
            + "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij"
            + "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d"
            + "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz"
            + "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz"
            + "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\","
            + "\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV"
            + "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV"
            + "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\","
            + "\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum"
            + "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx"
            + "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\","
            + "\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim"
            + "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu"
            + "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\","
            + "\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU"
            + "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9"
            + "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\","
            + "\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg"
            + "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx"
            + "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\","
            + "\"alg\":\"RS256\","
            + "\"kid\":\"2011-04-29\"}]}";
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        UnsupportedOperationException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithoutAlg_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));
  }

  @Test
  public void rsaWithoutKty_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{"
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithSmallN_getPrimitiveFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AAAwOQ\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithInvalidKty_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"EC\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithInvalidUse_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"invalid\",\"alg\":\"RS256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithInvalidKeyOps_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":[\"invalid\"]}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void rsaWithStringKeyOps_toPublicKeysetHandleFails() throws Exception {
    String jwksString =
        "{\"keys\":[{\"kty\":\"RSA\","
            + "\"n\":\"AM90NXQrAtt6KPSevzv9nbLJ2g_WPDH4zTwOo1slR8qC2chi6mH4TONOyAracdhQaoPwtMKge2ks"
            + "dJi1GaYwl975uvZEd9J1G078tlGrKPpy5I_OHseYDoeP8EgXawNII5ayFo-Ch_ZTxyzOuWmeb3DJft177D7T"
            + "Foz-zrMoTDGV4gwhBPeVfSk5DYvY06hF740KZq89nXBX_51KE5C-M9hBJMK9VA7BiGM8qjeu7l7ppXdzfvf6"
            + "azfkIogKMV7Xk0aw6nCW6h49BYuIu3TVjiToLEu5kX0z501whcCI8SA1tlicl7CzOCvVF70vg03RAB5vZQWY"
            + "2oFr3AwKBYDHvsc\","
            + "\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"key_ops\":\"verify\"}]}";
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(jwksString));

    String psJwksString = jwksString.replace("RS256", "PS256");
    assertThrows(
        GeneralSecurityException.class, () -> JwkSetConverter.toPublicKeysetHandle(psJwksString));
  }

  @Test
  public void jwksetWithDuplicateMapKey_fails() throws Exception {
    String jwkSetWithDuplicateMapKey =
        "{\"keys\":[{"
            + "\"kty\":\"EC\","
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
            + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
            + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]}]}";
    assertThrows(
        GeneralSecurityException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(jwkSetWithDuplicateMapKey));
  }

  @Test
  public void jwksetAsJsonArray_fails() throws Exception {
    String jwksetAsJsonArray =
        "[{"
            + "\"kty\":\"EC\","
            + "\"crv\":\"P-256\","
            + "\"x\":\"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA\","
            + "\"y\":\"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE\","
            + "\"use\":\"sig\",\"alg\":\"ES256\",\"key_ops\":[\"verify\"]}]";
    assertThrows(
        GeneralSecurityException.class,
        () -> JwkSetConverter.toPublicKeysetHandle(jwksetAsJsonArray));
  }

  @Test
  @SuppressWarnings("InlineMeInliner")
  public void deprecatedFromKeysetHandle_sameAs_fromPublicKeysetHandle()
      throws Exception {
    KeysetHandle handle = createEs256Keyset();
    assertEqualJwkSets(
        JwkSetConverter.fromKeysetHandle(handle, KeyAccess.publicAccess()),
        JwkSetConverter.fromPublicKeysetHandle(handle));
  }

  @Test
  @SuppressWarnings("InlineMeInliner")
  public void deprecatedToKeysetHandle_sameAs_toPublicKeysetHandle()
      throws Exception {
    KeysetHandle handle = JwkSetConverter.toPublicKeysetHandle(ES256_JWK_SET);
    KeysetHandle deprecatedHandle =
        JwkSetConverter.toKeysetHandle(ES256_JWK_SET, KeyAccess.publicAccess());
    assertEqualJwkSets(
      JwkSetConverter.fromPublicKeysetHandle(handle),
      JwkSetConverter.fromPublicKeysetHandle(deprecatedHandle));
  }
}
