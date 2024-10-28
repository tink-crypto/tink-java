// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link X25519Jce}.\
 *
 * <p>TODO(juerg): Also add tests with Conscrypt.
 */
@RunWith(JUnit4.class)
public final class X25519JceTest {

  boolean isJavaOneDotEight() {
    return System.getProperty("java.version").startsWith("1.8");
  }

  @Test
  public void isSupported_returnsTrueExceptForJavaOneDotEight() throws Exception {
    Assume.assumeTrue(!Util.isAndroid());

    if (isJavaOneDotEight()) {
      assertThat(X25519Jce.isSupported()).isFalse();
    } else {
      assertThat(X25519Jce.isSupported()).isTrue();
    }
  }

  @Test
  public void isSupported_onAndroid_returnsTrueForAndroid31AndAbove() throws Exception {
    Assume.assumeTrue(Util.isAndroid());

    if (Util.getAndroidApiLevel() < 31) {
      assertThat(X25519Jce.isSupported()).isFalse();
    } else {
      assertThat(X25519Jce.isSupported()).isTrue();
    }
  }

  /** Iteration test in Section 5.2 of RFC 7748. https://tools.ietf.org/html/rfc7748 */
  @Test
  public void testComputeSharedSecretWithRfcIteration() throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] k = new byte[32];
    k[0] = 9;
    byte[] prevK = k;
    k = X25519Jce.computeSharedSecret(k, prevK);
    assertEquals("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", Hex.encode(k));
    for (int i = 0; i < 999; i++) {
      byte[] tmp = k;
      k = X25519Jce.computeSharedSecret(k, prevK);
      prevK = tmp;
    }
    assertEquals("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Hex.encode(k));
    // Omitting 1M iteration to limit the test runtime.
  }

  @Test
  public void computeSharedSecret_ignoresMostSignificantBitInPublicKey() throws Exception {
    // first iteration of test in Section 5.2 of RFC 7748 with MSB set
    byte[] k = new byte[32];
    k[0] = 9;

    byte[] kWithMsb = new byte[32];
    kWithMsb[0] = 9;
    kWithMsb[31] = (byte) 0x80; // set MSB

    assertThat(Hex.encode(X25519.computeSharedSecret(k, kWithMsb)))
        .isEqualTo("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
  }

  @Test
  public void computeSharedSecret_withBannedPublicKey_throws() throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] privateKey = new byte[32];
    privateKey[0] = 9;

    // List of banned public keys from Curve25519.java.
    byte[][] bannedPublicKeys =
        new byte[][] {
          // 0
          new byte[] {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
          },
          // 1
          new byte[] {
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          },
          // 325606250916557431795983626356110631294008115727848805560023387167927233504
          new byte[] {
            (byte) 0xe0, (byte) 0xeb, (byte) 0x7a, (byte) 0x7c,
            (byte) 0x3b, (byte) 0x41, (byte) 0xb8, (byte) 0xae,
            (byte) 0x16, (byte) 0x56, (byte) 0xe3, (byte) 0xfa,
            (byte) 0xf1, (byte) 0x9f, (byte) 0xc4, (byte) 0x6a,
            (byte) 0xda, (byte) 0x09, (byte) 0x8d, (byte) 0xeb,
            (byte) 0x9c, (byte) 0x32, (byte) 0xb1, (byte) 0xfd,
            (byte) 0x86, (byte) 0x62, (byte) 0x05, (byte) 0x16,
            (byte) 0x5f, (byte) 0x49, (byte) 0xb8, (byte) 0x00,
          },
          // 39382357235489614581723060781553021112529911719440698176882885853963445705823
          new byte[] {
            (byte) 0x5f, (byte) 0x9c, (byte) 0x95, (byte) 0xbc,
            (byte) 0xa3, (byte) 0x50, (byte) 0x8c, (byte) 0x24,
            (byte) 0xb1, (byte) 0xd0, (byte) 0xb1, (byte) 0x55,
            (byte) 0x9c, (byte) 0x83, (byte) 0xef, (byte) 0x5b,
            (byte) 0x04, (byte) 0x44, (byte) 0x5c, (byte) 0xc4,
            (byte) 0x58, (byte) 0x1c, (byte) 0x8e, (byte) 0x86,
            (byte) 0xd8, (byte) 0x22, (byte) 0x4e, (byte) 0xdd,
            (byte) 0xd0, (byte) 0x9f, (byte) 0x11, (byte) 0x57
          },
          // 2^255 - 19 - 1
          new byte[] {
            (byte) 0xec, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f,
          },
          // 2^255 - 19
          new byte[] {
            (byte) 0xed, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f
          },
          // 2^255 - 19 + 1
          new byte[] {
            (byte) 0xee, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f
          }
        };
    for (byte[] bannedPublicKey : bannedPublicKeys) {
      assertThrows(
          InvalidKeyException.class,
          () -> X25519Jce.computeSharedSecret(privateKey, bannedPublicKey));
    }
  }

  @Test
  public void testGeneratePrivateKey_returnsRandomValidKeyPair() throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    X25519Jce.KeyPair keyPair = X25519Jce.generateKeyPair();
    assertThat(keyPair.privateKey).hasLength(32);
    assertThat(keyPair.publicKey).hasLength(32);
    assertThat(keyPair.publicKey).isEqualTo(X25519.publicFromPrivate(keyPair.privateKey));

    X25519Jce.KeyPair keyPair2 = X25519Jce.generateKeyPair();
    assertThat(keyPair2.privateKey).isNotEqualTo(keyPair.privateKey);
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsLessThan32Bytes()
      throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] privateKey = new byte[31];
    byte[] base = new byte[32];
    base[0] = 9;
    assertThrows(InvalidKeyException.class, () -> X25519Jce.computeSharedSecret(privateKey, base));
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsGreaterThan32Bytes()
      throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] privateKey = new byte[33];
    byte[] base = new byte[32];
    base[0] = 9;
    assertThrows(InvalidKeyException.class, () -> X25519Jce.computeSharedSecret(privateKey, base));
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsLessThan32Bytes()
      throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] privateKey = new byte[32];
    byte[] base = new byte[31];
    base[0] = 9;
    assertThrows(InvalidKeyException.class, () -> X25519Jce.computeSharedSecret(privateKey, base));
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsGreaterThan32Bytes()
      throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    byte[] privateKey = new byte[32];
    byte[] base = new byte[33];
    base[0] = 9;
    assertThrows(InvalidKeyException.class, () -> X25519Jce.computeSharedSecret(privateKey, base));
  }

  @Test
  public void testComputeSharedSecretWithWycheproofVectors() throws Exception {
    Assume.assumeTrue(X25519Jce.isSupported());

    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/x25519_test.json");
    ArrayList<String> errors = new ArrayList<>();
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");
      String curve = group.get("curve").getAsString();
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        String result = testcase.get("result").getAsString();
        String hexPubKey = testcase.get("public").getAsString();
        String hexPrivKey = testcase.get("private").getAsString();
        String expectedSharedSecret = testcase.get("shared").getAsString();
        assertThat(curve).isEqualTo("curve25519");
        try {
          String sharedSecret =
              Hex.encode(
                  X25519Jce.computeSharedSecret(Hex.decode(hexPrivKey), Hex.decode(hexPubKey)));
          if (result.equals("invalid")) {
            errors.add(
                "FAIL " + tcId + ": accepting invalid parameters, shared secret: " + sharedSecret);
          } else if (!expectedSharedSecret.equals(sharedSecret)) {
            errors.add(
                "FAIL "
                    + tcId
                    + ": incorrect shared secret, computed: "
                    + sharedSecret
                    + ", expected: "
                    + expectedSharedSecret);
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            errors.add("FAIL " + tcId + ": exception: " + ex.getMessage());
          }
        }
      }
    }
    assertThat(errors).isEmpty();
  }
}
