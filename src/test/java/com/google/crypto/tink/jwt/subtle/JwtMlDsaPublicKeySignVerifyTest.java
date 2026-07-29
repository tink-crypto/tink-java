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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.jwt.JwtInvalidException;
import com.google.crypto.tink.jwt.JwtMlDsaParameters;
import com.google.crypto.tink.jwt.JwtMlDsaPrivateKey;
import com.google.crypto.tink.jwt.JwtMlDsaPublicKey;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.jwt.internal.JsonUtil;
import com.google.crypto.tink.jwt.internal.JwtFormat;
import com.google.crypto.tink.signature.internal.MlDsaSignConscrypt;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Optional;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link JwtMlDsaPublicKeySign} and {@link JwtMlDsaPublicKeyVerify}. */
@RunWith(Theories.class)
public final class JwtMlDsaPublicKeySignVerifyTest {

  @BeforeClass
  public static void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // If Conscrypt is not available, tests requiring Conscrypt will be skipped.
    }
  }

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

  private static final String PRIVATE_KEY_MLDSA65_SEED_HEX =
      "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
  private static final String PUBLIC_KEY_MLDSA65_HEX =
      "1483236FC9F943D98417809E95405384530ED83E151E8465D34E4638F1F8D7058D62E1"
          + "9AB806490883A823176D4DC8A3C10C9960D0E948A9F7B62CA8E118DE5D7A05BB18E801"
          + "8B6CACB4FE7885490599939D90D004BD480B116F5D6627B6C4C1B2A1496CC3525EF9F1"
          + "9953EC63CDD6EBDB21D65B27C644194916AAD07CC559B08CFC1282D25D7276C9E5062E"
          + "0B1C4CF111C0A9DCC49BF40F5ED3C27CB4E78E39C1F068736A788E2ED4A02E9EF23EAC"
          + "E802CD295B6EB97D533091B3293D9BAD2938DFDECF2C4F9F6387B38A7FD22738A010B8"
          + "5949688650B6F063B6BC6350A1E84C869FB3BBCDC4BF6C0D0674D7C07F7AE78E4BBB30"
          + "2B6DB8488B5F9164E5E264682E45E71B58FC19ADF5EA892439EB352AFDDB63D22177AE"
          + "F17261909E3F87BCC7E1B1A58CD5DE8F8A886A12D7137CE5BFBD2C53ECEBFD1B9F2298"
          + "583D767E0DB5178B952F4D069D66FDEDCA1FBDCF8720AAAA5313C0500ECF95B9B70E7E"
          + "3D58DD2B57433D3A0637DF36E964B21F44F791B3AF9074D6DBC9A2FC041D9E22D5E387"
          + "C4081E6D4CCE6AB11FC8B4F2C718EB2A19924E3F17EA1F44D0084B5D5296A97A3624E4"
          + "E1F6CA05229F2888557AAB577FD72F8DC328F0E4F45DD13A191920F671ACE3BC29DC31"
          + "95E951D0F5EEAA095A3D5F20E4E4EA1AC157261C1C514AEB6940E63053AD68383F14E9"
          + "23602E6B241E9813246B47F009DB446FBF61246BAD7ED386647D020A854CCA39ECAE5F"
          + "A6D667CB6D433F02BC2FAB9F37096F3C127741EC02A46C81022E070AE1DF54623DF44C"
          + "5C744EDD0D3BC66581B8E1348E75B5C52D0E41BC71EDAD5B12DDA2280724B7D704BFF2"
          + "AF04505F65AE496DA86701D36BC9AFB0B199442A9C5C743D97880E89C8CCB34C518906"
          + "02627924316E79D4415CC1C2ED490A7A6EBB4B507181CFF18BB53A6B8F816C15A2EA86"
          + "67CE59EDBE8F42376001E31981310CA403E08328AA97828DC3A86C260819BC8DF72A3E"
          + "29657CA65B7763A54067958CCD6FD73DF789B306A37185C8117F0C86CF9D1C48D102EC"
          + "A8343F41F86F6084E2E72E6952357D7DC076A02A7CEF64724AE634E35712E291A24704"
          + "D2939717246371B42C11A672FE8FD31DA83FC3D5DE650FB2136A13A0D6229A115EA375"
          + "8E3AD0810A99944275FA8FECFD2BF1D130B40473F4ABF886485A1E36290DB437B331DB"
          + "303539F98D298183509D934F1A747AF29BC36BD7CA79E5D40D098EBFE61F400620B5B1"
          + "AFB81327342AADEC634F1A77DAE793D55A252D391AD155A6150AB049CBA0270F07936A"
          + "C21575BE6FAD53A0DC23F462E377F2C882391BAC1C17C11D18A677C3EFFACC4C6A9205"
          + "96F8654BB4955750BCBC18744375656F0B594D825872BB161A1B7FDFE7D01E7A19E02F"
          + "41AB9D02D1FED47161716172B8D68DB04E57C74053DAC785E9245BCC8DCA48C736457E"
          + "DEB8A075C1C42254E87110CBE4A909421AE6AECECE5D65834739BE6CAC51D1023CA25C"
          + "322B7B3461EC65168CCCF483A2668FB4527BCB312564C4097224DBC38AB397C3A7FD69"
          + "3B29992B9A773C43C0E9E94479F1762C91C367D9A079B13FDC38BD74F209E4D543ABF8"
          + "C9B14CED015599DFAE94723361ACBF6C1C0434DC0EFAF22C61057775F17F36D76FD75D"
          + "6BFCE7DCE922DCD7585AA33CAE7A6916C4E4AC5F86E4753F8CC798C20205C8C47656FB"
          + "AD7799B6A53DAE5DCB74CDB677FFFA66CBF2873A219413714578D6DA3B61AA29C494C2"
          + "F084BE1FA1C1CC40D1E4A424A4CEC73E455062B6E28C333839570D6FC6C08402A8D39F"
          + "145B97C3AACC6F24702E80F66F5D2FA1530CFF2A07486B3D38D8C9994EE633C2E527AF"
          + "49FBE26F634C6663CF95520E04A76F33E8876826B88887C4FE8FDEB1C50F55C7E7FBC2"
          + "A5077FA029DB53B7CD8FA3576BBC219AE7D7B21518FD94FA187D39D63187BF9F2BF259"
          + "2F1A7A35628137D82E50477FF3406DABFE558A3FD30D4E72D1F523EBF51DF6C7BFD9C8"
          + "5325897A7949113F30C9570F3A9FBAF73658430C3B2AFA43BF9D37D5410B5E416C5CF3"
          + "75CF9ADDCECF560E7D636C2D58B89D3E5A446201990EFFC467FFBA1009EE90D0F46BD2"
          + "D7018AE92CABECF62130BD7B4A077AF31882A713C73572387533EA249C9A18F0599C06"
          + "EE216CFC60F7498B2A75F3F8143D90A4ABF8651DEFAD600FD332AB09E3D8FAEFA2EC91"
          + "52EAF6F2BE6B78629022C0231849BE4C13FA08B827EC301150FA380663F737418C8BF0"
          + "700F4327F58C2256F8BA8B61176DFD1ACE6A81C19033E3D678A9CB234F85A5B6372EAF"
          + "1A1883F5ACED3ADF58B7FABFE44D986DBEDA351EA9DE5A841CD523336F986AB8FBBECF"
          + "1F52B1E87DBB3AC457A743FAE899A5BB3D10EAFC4D0808B7FA98C8068093CAE7A0BC20"
          + "74BAA701273734C28E97CD1102FFBCEBB83EBB17C9200BE6DBE58BC87C522E4D242542"
          + "04FD2EC52C60C1225649C3DEE17012C1CC0D5CDA0B2F0FC4F27274E04ACEDE68BACE92"
          + "E294B589BE45D74C5377AFEAC7182F4B702B5A50B49F1B32BD476483957C664676A819"
          + "FE6851F07768DA82261C75D53F8F04A64291A56E008B11AE09EE73923257EC195020D9"
          + "58F7B6D43ABA268978CB33B150A9C0DECAFBB36291257512CC7F2CB0B5564A0F81EF46"
          + "86838CDBFE10475520E6EF69047CCA864E50C86E9D91FC4EAE741D4BE8AD7B12952B76"
          + "C3429548169C370A7A5E2DB3FC809B9930952EF5AF9CDCCAF74FC13D0DB8D55862858E"
          + "47E4C6F66FDA9DA423B884DB6ED79D012587F757F0BD974680AD8E";

  private static final String PRIVATE_KEY_MLDSA87_SEED_HEX =
      "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
  private static final String PUBLIC_KEY_MLDSA87_HEX =
      "903EFBF16CD1F779825106F76DE12DF49CA4371B57117480702A1D94DD9C2042BDDA0535"
          + "9144230762A55D09AAF6961245E21B0D413DC2F39CF995327C6A1D52607BD9C3ADDF70D0"
          + "56361D8EB86C4B60FB7E0DE5638E4255454CD32EB48653F6A9047247233284953DA6D5F6"
          + "5AF1B59421673F6F9E89B58D483C6A9D3FC4EAC36CC3E489CA243F17DBCF0686B8B4DCC4"
          + "A37078B7A8B28218777C5C223ABA3123EAACD83CE2ED91ADA7EE0EFA23179F4457903417"
          + "EDA5350C4F4BD856DE0BC419C91B76E7DE9074C8EB4434D6055D80AC55BA276427FE3C84"
          + "4EC42BBD37EBC6CB142C6C1755F02F7F0C94631C987EC447060898B578144950E77CC51D"
          + "9797DF07025C8393ECB565C32EADD3179C696CB6AB5DE99B8FCB623E8C59D836AE3D4E87"
          + "9CFF4C4849880F0FBB293E7E637D3897D47CAA894656D58434244593D72A9781FF045A40"
          + "5F9C8886D1C2B828467A9BC28C4E29AECE6536ABF539B02AB03C876D899376CCDDA5C1AB"
          + "C4D3B2AAF3C5B3C7AD1956FCDB37F691E3E3DBB43EA967E733EC9E2D06D5A0E9FD67AF30"
          + "20CBAE5FCD7490E44F5E2646245FB1B92C93BFD6945093246D490A1A0FCDDD6D46BC4FA1"
          + "1137AA673D562488FA72CFB7FD210D3B3F04794415826861E87C50FD9B297F0EBE32153B"
          + "959D2BA684AA978827BEBF6B825C8C283388DE6237BA4B51A0D47F01C57951809B9592C9"
          + "35C9ACD64F45D08D5207BA365CA2AF7908C7791A4ECB8C20EFDED66EA640860293542479"
          + "7912E1363CB725C42DEEC98730FA99F17AF4DBAA825159164878F5B97FFB8959160EF304"
          + "E5E1A10D7F8671454B81081D7E24A75922EAAC49DD67C0CAAC7E24D3F914ED64FE618E26"
          + "860C6BE09A6BA56100687B3F0A61EAD9D55C984107B1DB88A1901ABFB93B0C3556E4A360"
          + "1E08BAE9BABAFB177D61702E0E8A357A2E760EDD39CF7A3C601C022C629607BEA771E408"
          + "BED8C96788200F16F3F76F9FB89B4F04389D40B76FF720CE478BACD77E659359D3803BAE"
          + "4BE439FD4A212B38E169BC1A1CF9594FEDF4A33ED7DA7B3E1D853D055D45C85B817805D2"
          + "5B59B52879B1EB7D59B723D05AFBF9F62FB1384A12748B0965FEAF5CCC5F45162F173836"
          + "D87B25907C262AA247C198E7EDFE7A472BC6553843E14C39E70DC993E566F0C339108FDF"
          + "32A7C9C9186A09BD5773B3D3393CAF8F8D3CCC2EDB7BA08FFA76C918669560CC170F69CA"
          + "41614ABFE6D230AC167A8F74F6664A23179580796EC0C01269BA2FEF895B36EC666E750D"
          + "CE0F76BB411867EC5152EF5B1A1AE2A857D791147EC9BF50D4B1E93562812787C7CD07B8"
          + "ED8CCBC294EC0721775C69731B3B471BA1621CD5BDFD11D5CA1D38EAD2A5B565D617A84D"
          + "08FF1F4AD5BEE0470D09B67C8D24C9018EB13205E6C86049B50C5DE2C52345E015732CF2"
          + "CE1DA9E5DF6CF0F54256B4D1D35E7193AFAACF616E28E761D977ABF2A54A3FE5D2823A27"
          + "5DCA6360394F0A7879AB61871BB8F15C9BF1D8990DD256FB7F07C90541FB2AF3C264E24C"
          + "8DC24BA47F6E23C9C17BA3162CCE979C063A47841A3D264CB8489082B3B1266539ABF7BB"
          + "6D6C277064980799793656E1F56906BA4541C19A8969CAE9FB98EE76500A895DF493FA7A"
          + "A4D8C4CF2F6AC554AEE05490C1CC888A8D9F30F477EF76DDC191794F0E92D3FEADE9B09B"
          + "1DE64ED0EBA2BFC82D6BFC693A48205310D32BDDBDD48333AC81DB32B404163E6A835A5D"
          + "CC3308AA0936F39E66CFD9173437B00BAE28D6D4DEFC2DDAD001E2A6E782BDEFAB164A21"
          + "4F36E95C307CA141A1F38D5EFA943779E9D01A72100F5DE76A072074286B5C6739B805EE"
          + "EFBA5639F2EE0880265ED091E4A2DEC230CF7453F4BDEC313E16297338A3E3F6E03C8FB1"
          + "208909A46DAD667D14BCB66F9D21573EFCBD3A4B2D8196C94EECC453D943C8B27D3E2BF9"
          + "B7DEFC2D00EFA3FD131BB48170A263A76366B78BBCC0D807CB0DCA4DAA9948C8240B537E"
          + "CC28FEFC3AB60D88A3486A5FC15C4BC6EC099E17D3A6B7B2761EA86980189E0E606BC0B1"
          + "E971532E627AC167726902A9D44C50BE24FFC34212B54DC596064E34B9821E6EA5A63892"
          + "F187901691F516649E7B01748AF1867A42A63BAB54BF551668D0825E64773752449C64EC"
          + "20842E5B8C6760D3379137EB9B5CAAAF469474AA9BB3C1F1A5C257363EB27BE4C7BC5C89"
          + "0F5D9532975051F2C4D62D14C0024289F240A6ABDE67C0896DE2EBC84FCFE99CEF7D15F7"
          + "9B221617D385782F60564B0B5911EE2D1BE5459058A37C578D0348D1C6E5976DED66B6BD"
          + "26D5ED78AFC59561BC28C75FA4B5048AA59D7D7010E22293A14D27B7B6F2ED3B8E5974BE"
          + "2E8E46850E30737896FA0A2104EF31ECB24AE8B16FB090AAF578811A60D864711B8BE1CB"
          + "538F69A3AF67EF47B81D50F07DDAFB394373F8C8678D938E618184955D14EAB88D715E1C"
          + "D22E33AAA7027378C392D76F458463F28A7F365EE708EEFEEFDDB261D0EC1F44EEF0E008"
          + "4DDDFCD7DD4F28019D9184091C6E2FF0DCEA261DA0EE746AB6EA802F63C1C374675B52B3"
          + "935B937EB7375EA28E3B5198C8FE2C9A677BE319933D981A19505E557A2ED6E007110F0D"
          + "95689ED23F62F20525E0029E4789933136B6CD3644F4D63B002A0B5942EAB5FF7B858B40"
          + "DC120D78BAE089A65EE5C7128DB3841DF863F476AC15029EC0147A0596D2293D1B5F48B1"
          + "3071822E2E8E9F525FFF083732BA87719FE92F6B264D9950458BD2C499E45AF0C6179B0F"
          + "116210844306EC289C478FA72F76A6AC46ACC55A32C19B2827127FA1A6D6F36B1EF50CE6"
          + "7A458643CAAF9B8A9FE3F28EBB7896520D14827F64CA7D6EFD9B8599EDE0D32F97483875"
          + "69ABB52028E042EFC659AEDE4EF4EE4B85FFCD17455A522ADF712C6675F46A3DBF341E6F"
          + "C748CC19CE8306C1E3BB762F69B171446D36E63A299D0D68B88ECEE3D7FA919BF402CA3E"
          + "BD46FAD001BC250C8177CD43AEEF01D32417303B65728FD25DCEB9F1289815C3132EC1E5"
          + "7A376F1C19D6901C398C58A3D7DA3AE23C399EB71FA31A86D1CDA4940B624D28AC93DA1E"
          + "9FAC52026C3A110250B5E95F78229059AEB9703377671E47A09496F1DC333BE19C537514"
          + "AB5255A27838CB039CB7817D35C387F3A19E21437EE1CDD2C7EF58830284EAF677DCE2D2"
          + "1D4B1ED54E2B2B15977A983CF939A9F5AC5598DD73E50A43CDB6BD4CA9F08B78CD9C96CE"
          + "D06554DB1CF4A6749FD50B062C702A6A2EE9F6102D7E848254593E430EC9A659E0104602"
          + "050B49B70C4F182327F3EBBC4214FA6BD034E2222CA012B3BC288413F6ECE618EAF3ACF1"
          + "B0D9AA94A102DA9B56329F4C808AC33D35AF54E6D4C1D12E60734EB0289F1674255AD4FA"
          + "CA9644C36388E65C1DA898E4CD6531E89592E1E57BB2988D5788EBE1B013283DDDFA346C"
          + "DA5B224F5F8BEFFAC5CA521BC546AA3F1EECB254C597314657DDA91727BA42929B3993C3"
          + "C44ED3CE00AA1AF9B00CF9EEFD7530ACF29C50BD0706620372424F58BFB356D28EF5A8D9"
          + "0403C52D62DD2F92A19B75E6C46CB4EAC77A9102A6DCBB1DCEA05A28688B94ED3966E956"
          + "4519580803795F038255CCF0AB91762898942AFA38E4BF7839B3DEC19D2444D5237212E1"
          + "5A491D1F5636D41D0CC3751D96D856F1CD4BF2A3FE1AE8168B2475D11051EB1980C39FE1";

  public static class TestVector {
    final JwtMlDsaParameters.KidStrategy kidStrategy;
    final JwtMlDsaParameters.Algorithm algorithm;
    final Optional<String> kid;
    final JwtMlDsaPrivateKey privateKey;

    TestVector(
        JwtMlDsaParameters.KidStrategy kidStrategy,
        JwtMlDsaParameters.Algorithm algorithm,
        Optional<String> kid,
        @Nullable Integer idRequirement,
        String privateSeedHex,
        String publicKeyHex) {
      this.kidStrategy = kidStrategy;
      this.algorithm = algorithm;
      this.kid = kid;

      try {
        JwtMlDsaParameters parameters = JwtMlDsaParameters.create(kidStrategy, algorithm);
        JwtMlDsaPublicKey.Builder builder =
            JwtMlDsaPublicKey.builder()
                .setParameters(parameters)
                .setPublicKeyBytes(Bytes.copyFrom(Hex.decode(publicKeyHex)));
        if (idRequirement != null) {
          builder.setIdRequirement(idRequirement);
        }
        if (kidStrategy == JwtMlDsaParameters.KidStrategy.CUSTOM) {
          builder.setCustomKid(kid.get());
        }
        JwtMlDsaPublicKey publicKey = builder.build();
        SecretBytes privateSeed =
            SecretBytes.copyFrom(Hex.decode(privateSeedHex), InsecureSecretKeyAccess.get());
        this.privateKey = JwtMlDsaPrivateKey.create(publicKey, privateSeed);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  @DataPoints("testVectors")
  public static final TestVector[] testVectors = {
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944,
        PRIVATE_KEY_MLDSA44_SEED_HEX,
        PUBLIC_KEY_MLDSA44_HEX),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.of("GsapRA"),
        /* idRequirement= */ 0x1ac6a944,
        PRIVATE_KEY_MLDSA65_SEED_HEX,
        PUBLIC_KEY_MLDSA65_HEX),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_65,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null,
        PRIVATE_KEY_MLDSA65_SEED_HEX,
        PUBLIC_KEY_MLDSA65_HEX),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.IGNORED,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.empty(),
        /* idRequirement= */ null,
        PRIVATE_KEY_MLDSA87_SEED_HEX,
        PUBLIC_KEY_MLDSA87_HEX),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_87,
        /* kid= */ Optional.of("custom_kid_87"),
        /* idRequirement= */ null,
        PRIVATE_KEY_MLDSA87_SEED_HEX,
        PUBLIC_KEY_MLDSA87_HEX),
    new TestVector(
        JwtMlDsaParameters.KidStrategy.CUSTOM,
        JwtMlDsaParameters.Algorithm.ML_DSA_44,
        /* kid= */ Optional.of("custom_kid_44"),
        /* idRequirement= */ null,
        PRIVATE_KEY_MLDSA44_SEED_HEX,
        PUBLIC_KEY_MLDSA44_HEX),
  };

  @Theory
  public void createSignVerify_succeeds(@FromDataPoints("testVectors") TestVector testVector)
      throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVector.privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVector.privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  @Test
  public void createSignVerify_differentKey_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    JwtPublicKeyVerify otherVerifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[1].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Test
  public void createSignVerify_headerModification_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Test
  public void createSignVerify_payloadModification_throws() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtPublicKeySign signer = JwtMlDsaPublicKeySign.create(testVectors[0].privateKey);
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
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

  @Test
  public void createSignVerify_withDifferentHeaders() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    PublicKeySign nonJwtSigner =
        MlDsaSignConscrypt.create(testVectors[2].privateKey.getMlDsaPrivateKey());
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[2].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "ML-DSA-65");
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
    unknownKidHeader.addProperty("alg", "ML-DSA-65");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    PublicKeySign nonJwtSigner =
        MlDsaSignConscrypt.create(testVectors[0].privateKey.getMlDsaPrivateKey());
    JwtPublicKeyVerify verifier =
        JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey());
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    String kid = testVectors[0].privateKey.getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");

    // valid token
    JsonObject validHeader = new JsonObject();
    validHeader.addProperty("alg", "ML-DSA-44");
    validHeader.addProperty("kid", kid);
    String validToken = generateSignedCompact(nonJwtSigner, validHeader, payload);
    Object unused = verifier.verifyAndDecode(validToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "ML-DSA-44");
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
    headerWithUnknownKid.addProperty("alg", "ML-DSA-44");
    headerWithUnknownKid.addProperty("kid", "unknown");
    String tokenWithUnknownKid = generateSignedCompact(nonJwtSigner, headerWithUnknownKid, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(tokenWithUnknownKid, validator));
  }

  private static JwtMlDsaPrivateKey withCustomKid(JwtMlDsaPrivateKey privateKey, String customKid)
      throws GeneralSecurityException {
    JwtMlDsaParameters customKidParameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.CUSTOM, privateKey.getParameters().getAlgorithm());
    JwtMlDsaPublicKey customKidPublicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(customKidParameters)
            .setPublicKeyBytes(
                privateKey.getPublicKey().getMlDsaPublicKey().getSerializedPublicKey())
            .setCustomKid(customKid)
            .build();
    return JwtMlDsaPrivateKey.create(customKidPublicKey, privateKey.getPrivateSeed());
  }

  private static JwtMlDsaPrivateKey withIgnoredKid(JwtMlDsaPrivateKey privateKey)
      throws GeneralSecurityException {
    JwtMlDsaParameters ignoredKidParameters =
        JwtMlDsaParameters.create(
            JwtMlDsaParameters.KidStrategy.IGNORED, privateKey.getParameters().getAlgorithm());
    JwtMlDsaPublicKey ignoredKidPublicKey =
        JwtMlDsaPublicKey.builder()
            .setParameters(ignoredKidParameters)
            .setPublicKeyBytes(
                privateKey.getPublicKey().getMlDsaPublicKey().getSerializedPublicKey())
            .build();
    return JwtMlDsaPrivateKey.create(ignoredKidPublicKey, privateKey.getPrivateSeed());
  }

  @Test
  public void signAndVerifyWithCustomKid() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtMlDsaPrivateKey keyWithoutKid = withIgnoredKid(testVectors[0].privateKey);
    JwtMlDsaPrivateKey keyWithKid =
        withCustomKid(
            testVectors[0].privateKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtPublicKeySign signerWithKid = JwtMlDsaPublicKeySign.create(keyWithKid);
    JwtPublicKeySign signerWithoutKid = JwtMlDsaPublicKeySign.create(keyWithoutKid);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo("Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid =
        JwtMlDsaPublicKeyVerify.create(keyWithoutKid.getPublicKey());
    JwtPublicKeyVerify verifierWithKid = JwtMlDsaPublicKeyVerify.create(keyWithKid.getPublicKey());

    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
  }

  @Test
  public void signAndVerifyWithWrongCustomKid_fails() throws Exception {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return;
    }
    JwtMlDsaPrivateKey keyWithKid = withCustomKid(testVectors[0].privateKey, "kid");
    JwtMlDsaPrivateKey keyWithWrongKid = withCustomKid(testVectors[0].privateKey, "wrong kid");

    JwtPublicKeySign signerWithKid = JwtMlDsaPublicKeySign.create(keyWithKid);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        JwtMlDsaPublicKeyVerify.create(keyWithWrongKid.getPublicKey());

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void throwsIfMlDsaNotSupported() throws Exception {
    assumeFalse(MlDsaVerifyConscrypt.isSupported());

    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaPublicKeySign.create(testVectors[0].privateKey));
    assertThrows(
        GeneralSecurityException.class,
        () -> JwtMlDsaPublicKeyVerify.create(testVectors[0].privateKey.getPublicKey()));
  }
}
