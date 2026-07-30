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

package com.google.crypto.tink.jwt.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.ProtoParametersSerialization;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtMlDsaProtoSerializationTest {
  // https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/mldsa_44_sign_seed_test.json
  private static final String PRIVATE_KEY_MLDSA44_SEED_HEX =
      "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
  private static final String PUBLIC_KEY_MLDSA44_HEX =
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

  @Test
  public void serializeParseParameters_kidStrategyIsIgnored_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    ProtoParametersSerialization serialization =
        JwtMlDsaProtoSerialization.serializeParameters(parameters);
    Parameters parsed = JwtMlDsaProtoSerialization.parseParameters(serialization);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParseParameters_kidStrategyBase64_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
            JwtMlDsaParameters.Algorithm.ML_DSA_44);

    ProtoParametersSerialization serialization =
        JwtMlDsaProtoSerialization.serializeParameters(parameters);
    Parameters parsed = JwtMlDsaProtoSerialization.parseParameters(serialization);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void serializeParameters_customKid_fails() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, JwtMlDsaParameters.Algorithm.ML_DSA_44);

    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaProtoSerialization.serializeParameters(parameters));
  }

  @Test
  public void serializeParsePublicKey_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(Bytes.copyFrom(Hex.decode(PUBLIC_KEY_MLDSA44_HEX)))
            .build();

    ProtoKeySerialization serialization =
        JwtMlDsaProtoSerialization.serializePublicKey(publicKey, /* access= */ null);
    JwtMlDsaPublicKey parsed =
        JwtMlDsaProtoSerialization.parsePublicKey(serialization, /* access= */ null);

    assertThat(parsed.equalsKey(publicKey)).isTrue();
  }

  @Test
  public void serializeParsePrivateKey_works() throws Exception {
    JwtMlDsaParameters parameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, JwtMlDsaParameters.Algorithm.ML_DSA_44);
    JwtMlDsaPublicKey publicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicKeyBytes(Bytes.copyFrom(Hex.decode(PUBLIC_KEY_MLDSA44_HEX)))
            .build();
    JwtMlDsaPrivateKey privateKey =
        JwtMlDsaPrivateKey.create(
            publicKey,
            SecretBytes.copyFrom(
                Hex.decode(PRIVATE_KEY_MLDSA44_SEED_HEX), InsecureSecretKeyAccess.get()));

    ProtoKeySerialization serialization =
        JwtMlDsaProtoSerialization.serializePrivateKey(privateKey, InsecureSecretKeyAccess.get());
    JwtMlDsaPrivateKey parsed =
        JwtMlDsaProtoSerialization.parsePrivateKey(serialization, InsecureSecretKeyAccess.get());

    assertThat(parsed.equalsKey(privateKey)).isTrue();
  }
}
