// Copyright 2020 Google LLC
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

package com.google.crypto.tink.hybrid.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for RsaKem * */
@RunWith(JUnit4.class)
public final class RsaKemTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void generateSecret() throws Exception {
    BigInteger max = new BigInteger(2048, new Random());
    int maxSizeInBytes = RsaKem.bigIntSizeInBytes(max);

    Set<String> secrets = new TreeSet<>();
    for (int i = 0; i < 100; i++) {
      byte[] secret = RsaKem.generateSecret(max);
      BigInteger secretBigInt = new BigInteger(1, secret);
      secrets.add(new String(secret, UTF_8));

      assertThat(secret).hasLength(maxSizeInBytes);
      assertThat(secretBigInt.signum()).isEqualTo(1);
      assertThat(secretBigInt.compareTo(max)).isLessThan(0);
    }
    assertThat(secrets).hasSize(100);
  }

  // This test vector is from https://www.shoup.net/iso/std6.pdf, C.6.3
  @Test
  public void rsaEncryptDecryptWithTestVector_works() throws Exception {
    BigInteger n =
        new BigInteger(
            "58881133325026912517619364310092848849666407571798023374905464783262"
                + "38537107326596800820237597139824869184990638749556269785797065508097"
                + "452399642780486933");
    BigInteger e = new BigInteger("65537");
    BigInteger d =
        new BigInteger(
            "32023135558599481863153745244741739956797835803921402370443497280464"
                + "79396037520308981353808895461806395564474639124525446044708705259675"
                + "840210989546479265");
    byte[] r =
        Hex.decode(
            "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741"
                + "52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    byte[] c0 =
        Hex.decode(
            "4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ff"
                + "cf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0");

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(n, d));
    PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));

    byte[] encrypted = RsaKem.rsaEncrypt(publicKey, r);
    byte[] decrypted = RsaKem.rsaDecrypt(privateKey, encrypted);

    assertThat(encrypted).isEqualTo(c0);
    assertThat(decrypted).isEqualTo(r);
  }

  @Test
  public void rsaEncrypt_inputTooLarge_throws() throws Exception {
    BigInteger n =
        new BigInteger(
            "58881133325026912517619364310092848849666407571798023374905464783262"
                + "38537107326596800820237597139824869184990638749556269785797065508097"
                + "452399642780486933");
    BigInteger e = new BigInteger("65537");

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));

    // This input has 65 bytes, but only 64 bits are valid.
    byte[] inputTooLarge =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                + "40");
    // This throws an IllegalBlockSizeException
    assertThrows(GeneralSecurityException.class, () -> RsaKem.rsaEncrypt(publicKey, inputTooLarge));

    // This input has 64 bytes, but it is larger than the modulus.
    byte[] inputTooLarge2 =
        Hex.decode(
            "ffff02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    // this sometimes throws SignatureException, sometimes BadPaddingException.
    assertThrows(
        GeneralSecurityException.class, () -> RsaKem.rsaEncrypt(publicKey, inputTooLarge2));
  }

  @Test
  public void rsaDecrypt_inputTooLarge_throws() throws Exception {
    BigInteger n =
        new BigInteger(
            "58881133325026912517619364310092848849666407571798023374905464783262"
                + "38537107326596800820237597139824869184990638749556269785797065508097"
                + "452399642780486933");
    BigInteger d =
        new BigInteger(
            "32023135558599481863153745244741739956797835803921402370443497280464"
                + "79396037520308981353808895461806395564474639124525446044708705259675"
                + "840210989546479265");

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(n, d));

    // This input has 65 bytes, but only 64 bits are valid.
    byte[] inputTooLarge =
        Hex.decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                + "40");
    // This throws an IllegalBlockSizeException
    assertThrows(
        GeneralSecurityException.class, () -> RsaKem.rsaDecrypt(privateKey, inputTooLarge));

    // This input has 64 bytes, but it is larger than the modulus.
    byte[] inputTooLarge2 =
        Hex.decode(
            "ffff02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    // this sometimes throws SignatureException, sometimes BadPaddingException.
    assertThrows(
        GeneralSecurityException.class, () -> RsaKem.rsaDecrypt(privateKey, inputTooLarge2));
  }
}
