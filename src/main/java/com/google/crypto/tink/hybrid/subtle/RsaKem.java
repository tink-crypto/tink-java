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

import com.google.crypto.tink.internal.BigIntegerEncoding;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;

class RsaKem {
  static final byte[] EMPTY_AAD = new byte[0];
  static final int MIN_RSA_KEY_LENGTH_BITS = 2048;

  private RsaKem() {}

  static void validateRsaModulus(BigInteger mod) throws GeneralSecurityException {
    if (mod.bitLength() < MIN_RSA_KEY_LENGTH_BITS) {
      throw new GeneralSecurityException(
          String.format(
              "RSA key must be of at least size %d bits, but got %d",
              MIN_RSA_KEY_LENGTH_BITS, mod.bitLength()));
    }
  }

  static int bigIntSizeInBytes(BigInteger mod) {
    return (mod.bitLength() + 7) / 8;
  }

  /**
   * This implements RsaTransform from https://www.shoup.net/iso/std6.pdf, 11.2, where alpha is the
   * public exponent e from the public key.
   *
   * <p>Throws {@link GeneralSecurityException} if the input is too large.
   */
  static byte[] rsaEncrypt(PublicKey publicKey, byte[] x) throws GeneralSecurityException {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    try {
      return rsaCipher.doFinal(x);
    } catch (RuntimeException e) {
      // On Android API version 27, inputs of the correct size but larger than the modulus may
      // throw a RuntimeException, but they should instead throw a GeneralSecurityException.
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * This implements RsaTransform from https://www.shoup.net/iso/std6.pdf, 11.2, where alpha is the
   * private exponent d from the private key.
   *
   * <p>Throws {@link GeneralSecurityException} if the input is too large.
   */
  static byte[] rsaDecrypt(PrivateKey privateKey, byte[] x) throws GeneralSecurityException {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
    try {
      return rsaCipher.doFinal(x);
    } catch (RuntimeException e) {
      // On Android API version 27, inputs of the correct size but larger than the modulus may
      // throw a RuntimeException, but they should instead throw a GeneralSecurityException.
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Generates a random BigInteger in (0, max) (excluding 0 and max) and converts the result to a
   * byte array having the same length as max.
   */
  static byte[] generateSecret(BigInteger max) {
    int maxSizeInBytes = bigIntSizeInBytes(max);
    Random rand = new SecureRandom();
    BigInteger r;
    do {
      r = new BigInteger(max.bitLength(), rand);
    } while (r.signum() <= 0 || r.compareTo(max) >= 0);
    try {
      return BigIntegerEncoding.toBigEndianBytesOfFixedLength(r, maxSizeInBytes);
    } catch (GeneralSecurityException e) {
      // This can only happen if maxSizeInBytes is too small for r, which is impossible here.
      throw new IllegalStateException("Unable to convert BigInteger to byte array", e);
    }
  }

  static KeyPair generateRsaKeyPair(int keySize) {
    KeyPairGenerator rsaGenerator;
    try {
      rsaGenerator = KeyPairGenerator.getInstance("RSA");
      rsaGenerator.initialize(keySize);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("No support for RSA algorithm.", e);
    }
    return rsaGenerator.generateKeyPair();
  }
}
