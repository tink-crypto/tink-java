// Copyright 2018 Google LLC
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
package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Hex;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPkcs1VerifyKeyManager. */
@RunWith(JUnit4.class)
public final class RsaSsaPkcs1VerifyKeyManagerTest {
  @BeforeClass
  public static void beforeClass() throws Exception {
    PublicKeySignWrapper.register();
    PublicKeyVerifyWrapper.register();
    RsaSsaPkcs1SignKeyManager.registerPair(/* newKeyAllowed= */ true);
  }

  static class NistTestVector {
    byte[] msg;
    byte[] sig;
    RsaSsaPkcs1PublicKey publicKey;

    public NistTestVector(
        String modulusHex,
        String exponentHex,
        String msg,
        String sig,
        RsaSsaPkcs1Parameters.HashType hashType)
        throws Exception {
      BigInteger modulus = new BigInteger(modulusHex, 16);
      BigInteger exponent = new BigInteger(exponentHex, 16);
      RsaSsaPkcs1Parameters parameters =
          RsaSsaPkcs1Parameters.builder()
              .setModulusSizeBits(modulus.bitLength())
              .setPublicExponent(exponent)
              .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
              .setHashType(hashType)
              .build();
      this.publicKey =
          RsaSsaPkcs1PublicKey.builder().setParameters(parameters).setModulus(modulus).build();
      this.msg = Hex.decode(msg);
      this.sig = Hex.decode(sig);
    }
  }

  // Test vector from
  // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
  static NistTestVector[] nistTestVectors;

  @BeforeClass
  public static void setUpNistTestVectors() throws Exception {
    nistTestVectors =
        new NistTestVector[] {
          new NistTestVector(
              "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb",
              "49d2a1",
              "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea",
              "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405",
              RsaSsaPkcs1Parameters.HashType.SHA256),
          new NistTestVector(
              "9689eb163a617c0abbf01ddc0e6d88c37f8a6b0baec0f6cab8f8a683f372a53d028253a6ba502da462adaf4fd87c8dc2b03b6c07c2b6aacab1d8c8bd043d89f4effe72ea2547c73c6366a2efab9c916945820fb880890bc085564e57ee76f7107a008f71e941e9fd631aec78f82e410ea9c893faa3d553cd1ca628af1087ca1b0c6aef3b66edcee14d1d7dc48293ddd7deed1ccbe487c957585abb9509151038d53f46b068e3e139c7689bf8e8d38669896b8d082e65e458e1f82b8e8ec926e7aa0f97d08526e9636f2c00af4c2bd3d8bffc4bb93cd47b09af18883e11b639d47938d036f7cfeb77db74a2c09a6dee9df98b18eff2fda7d3f4135083bb3b59e2172244ec37bdbdcfe6e199d36dc949cda1cca123fb2be07803d003d76af3d7164453df77d44c7f2599636ca44d0b7a46218326b0c814ed322b9c4279b060f1b9e14b70f55a3751c4343763cdbf9c14637d2210c59fbd037be17ea6706846fdc7b9ab90278c01c458e64442f9256f3ad1cbceb22959d495063aaca1a3959eae03",
              "fa3751",
              "6459ea1d443df706907ffdd3ca2f193f93f5a349b50357d26748b767cde6ab5cbfe76b1acb2b9eb97da5c4d2ddc8d18e3a3b1a0326d475c1c2c49ca73c0fd3fc9540cbbba85ac52d6811fabd693a3b09a281d535715ab784df3ad7292606d15a70ccd1a7e2b1b48ad92a6a3f736f9fd5522d9a869c7b654446102e9493b3ed9f",
              "2b72942573b825cd1f0172119c23440a2b384b7f2a3c5582bb02f764e2b159ea9ad880ca61b3df7ca249134f4bec285083c7ebf984b192808e916af687ef6c6a9a6722a4fa9189fac1521d03853f3dd5a95ff4b9dbdbf3c7077f720650ead01945ab5bfee582ac1643526fbf68efe1bb3b6f7d2b4b01f2155aaea38a2c7ed29add23ee791a703d11e3b1b7c500d9a6b647c1337bf537c071e5bada6faa025bcaf5e5d1196998909c3d64758826939ae7fe1466dc6efc10a2b25e21186c2d135ceace33cdf490b13a0d10c2527e04200aa70bc1d4f3cfb04b5d2bc17aee881d3a788401f45443470bc639232088a9553c8d792aa5707654f075476a66b86368d5a92b4c84a3b4baba1b0b98bdebb85b48b82b8409f2e9c1aa500670329ff3b6e83e25c561110d47b2fe93ea2946a74f9730da9b7d126f8d7c3fa4a51fc30144a827831c186390998d552a1b677afe5afee46e9d4a5774a56355a4d1967677e75d176aef71c3fa061644d7a9582385877de67f87724b0a6e868f3a2eeafb68c53b",
              RsaSsaPkcs1Parameters.HashType.SHA512),
        };
  }

  @Test
  public void testNistTestVector() throws Exception {
    for (NistTestVector t : nistTestVectors) {
      KeysetHandle handle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(t.publicKey).withRandomId().makePrimary())
              .build();
      PublicKeyVerify verifier =
          handle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
      try {
        verifier.verify(t.sig, t.msg);
      } catch (GeneralSecurityException e) {
        fail("Valid signature, should not throw exception" + e);
      }
    }
  }

  @Test
  public void test_serializeAndParse_works() throws Exception {
    SignatureTestVector testVector = RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors()[0];
    com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey key =
        (com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey)
            testVector.getPrivateKey().getPublicKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).withFixedId(1951).makePrimary();
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    byte[] serializedHandle = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsedHandle = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedHandle);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
                    PublicKeyVerify.class))
        .isNotNull();
  }
}
