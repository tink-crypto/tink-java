// Copyright 2024 Google LLC
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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * X25519 implementation using JCE.
 *
 * <p>We use the PKCS8 and X509 encodings of the private and the public keys, because they are
 * supported by all JCE implementations and they are easier to convert from and to their raw 32-byte
 * encodings.
 */
public final class X25519Jce {
  public static final int PRIVATE_KEY_LEN = 32;
  private static final int PUBLIC_KEY_LEN = 32;

  private static final byte[] X25519_PKCS8_PREFIX =
      new byte[] {
        0x30, 0x2e, // Sequence: 46 bytes
        0x02, 0x01, 0x00, // Integer: 0 (version)
        0x30, 0x05, // Sequence: 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x6e, // OID: 1.3.101.112 (X25519)
        0x04, 0x22, 0x04, 0x20, // Octet string: 32 bytes
      };

  private static final byte[] X25519_X509_PREFIX =
      new byte[] {
        0x30, 0x2a, // Sequence: 42 bytes
        0x30, 0x05, // Sequence: 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x6e, // OID: 1.3.101.110 (X25519)
        0x03, 0x21, 0x00, // Bit string: 256 bits
      };

  /** Returns true if the JCE supports X25519. */
  public static boolean isSupported() {
    try {
      KeyPairGenerator unusedKeyPairGenerator = EngineFactory.KEY_PAIR_GENERATOR.getInstance("XDH");
      KeyFactory unusedKeyFactory = EngineFactory.KEY_FACTORY.getInstance("XDH");
      KeyAgreement unusedKeyAgreement = EngineFactory.KEY_AGREEMENT.getInstance("XDH");
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private X25519Jce() {}

  /** An X25519 key pair. */
  public static final class KeyPair {
    public final byte[] privateKey;
    public final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  }

  public static KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("XDH");
    keyGen.initialize(/* keysize= */ 255);
    java.security.KeyPair keyPair = keyGen.generateKeyPair();

    byte[] pkcs8EncodedPrivateKey = keyPair.getPrivate().getEncoded();
    if (pkcs8EncodedPrivateKey.length != PRIVATE_KEY_LEN + X25519_PKCS8_PREFIX.length) {
      throw new GeneralSecurityException("Invalid encoded private key length");
    }
    if (!isPrefix(X25519_PKCS8_PREFIX, pkcs8EncodedPrivateKey)) {
      throw new GeneralSecurityException("Invalid encoded private key prefix");
    }
    byte[] privateKey =
        Arrays.copyOfRange(
            pkcs8EncodedPrivateKey, X25519_PKCS8_PREFIX.length, pkcs8EncodedPrivateKey.length);

    byte[] x509EncodedPublicKey = keyPair.getPublic().getEncoded();
    if (x509EncodedPublicKey.length != PUBLIC_KEY_LEN + X25519_X509_PREFIX.length) {
      throw new GeneralSecurityException("Invalid encoded public key length");
    }
    if (!isPrefix(X25519_X509_PREFIX, x509EncodedPublicKey)) {
      throw new GeneralSecurityException("Invalid encoded public key prefix");
    }
    byte[] publicKey =
        Arrays.copyOfRange(
            x509EncodedPublicKey, X25519_X509_PREFIX.length, x509EncodedPublicKey.length);

    return new KeyPair(privateKey, publicKey);
  }

  public static byte[] computeSharedSecret(byte[] privateValue, byte[] peersPublicValue)
      throws GeneralSecurityException {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance("XDH");

    if (privateValue.length != PRIVATE_KEY_LEN) {
      throw new InvalidKeyException("Invalid X25519 private key");
    }
    KeySpec privateKeySpec =
        new PKCS8EncodedKeySpec(Bytes.concat(X25519_PKCS8_PREFIX, privateValue));
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

    if (peersPublicValue.length != PUBLIC_KEY_LEN) {
      throw new InvalidKeyException("Invalid X25519 public key");
    }
    KeySpec publicKeySpec =
        new X509EncodedKeySpec(Bytes.concat(X25519_X509_PREFIX, peersPublicValue));
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

    KeyAgreement keyAgreementA = KeyAgreement.getInstance("XDH");
    keyAgreementA.init(privateKey);
    keyAgreementA.doPhase(publicKey, /* lastPhase= */ true);
    return keyAgreementA.generateSecret();
  }
}
