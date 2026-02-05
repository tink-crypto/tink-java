// Copyright 2017 Google LLC
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

package com.google.crypto.tink;

import com.google.crypto.tink.internal.PemUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.annotation.Nullable;

/** PEM key types that Tink supports */
public enum PemKeyType {
  // RSASSA-PSS 2048 bit key with a SHA256 digest.
  RSA_PSS_2048_SHA256("RSA", "RSASSA-PSS", 2048, HashType.SHA256),
  // RSASSA-PSS 3072 bit key with a SHA256 digest.
  RSA_PSS_3072_SHA256("RSA", "RSASSA-PSS", 3072, HashType.SHA256),
  // RSASSA-PSS 4096 bit key with a SHA256 digest.
  RSA_PSS_4096_SHA256("RSA", "RSASSA-PSS", 4096, HashType.SHA256),
  // RSASSA-PSS 4096 bit key with a SHA512 digest.
  RSA_PSS_4096_SHA512("RSA", "RSASSA-PSS", 4096, HashType.SHA512),

  // RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
  RSA_SIGN_PKCS1_2048_SHA256("RSA", "RSASSA-PKCS1-v1_5", 2048, HashType.SHA256),
  // RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
  RSA_SIGN_PKCS1_3072_SHA256("RSA", "RSASSA-PKCS1-v1_5", 3072, HashType.SHA256),
  // RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
  RSA_SIGN_PKCS1_4096_SHA256("RSA", "RSASSA-PKCS1-v1_5", 4096, HashType.SHA256),
  // RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
  RSA_SIGN_PKCS1_4096_SHA512("RSA", "RSASSA-PKCS1-v1_5", 4096, HashType.SHA512),

  // ECDSA on the NIST P-256 curve with a SHA256 digest and SignatureEncoding DER.
  ECDSA_P256_SHA256("EC", "ECDSA", 256, HashType.SHA256),
  // ECDSA on the NIST P-384 curve with a SHA384 digest and SignatureEncoding DER.
  ECDSA_P384_SHA384("EC", "ECDSA", 384, HashType.SHA384),
  // ECDSA on the NIST P-521 curve with a SHA512 digest and SignatureEncoding DER.
  ECDSA_P521_SHA512("EC", "ECDSA", 521, HashType.SHA512);

  public final String keyType;
  public final String algorithm;
  public final int keySizeInBits;
  public final HashType hash;

  PemKeyType(String keyType, String algorithm, int keySizeInBits, HashType hash) {
    this.keyType = keyType;
    this.algorithm = algorithm;
    this.keySizeInBits = keySizeInBits;
    this.hash = hash;
  }

  /**
   * Reads a single key from {@code reader}.
   *
   * @return a {@link Key} or null if the reader doesn't contain a valid PEM.
   */
  @Nullable
  public Key readKey(BufferedReader reader) throws IOException {
    EncodedKeySpec keySpec = PemUtil.parsePemToKeySpec(reader);
    if (keySpec == null) {
      return null;
    }
    try {
      if (keySpec instanceof X509EncodedKeySpec) {
        return getPublicKey(keySpec.getEncoded());
      } else if (keySpec instanceof PKCS8EncodedKeySpec) {
        return getPrivateKey(keySpec.getEncoded());
      }
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      return null;
    }
    return null;
  }

  private Key getPublicKey(final byte[] key) throws GeneralSecurityException {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance(this.keyType);
    return validate(keyFactory.generatePublic(new X509EncodedKeySpec(key)));
  }

  private Key getPrivateKey(final byte[] key) throws GeneralSecurityException {
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance(this.keyType);
    return validate(keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key)));
  }

  @CanIgnoreReturnValue
  private Key validate(Key key) throws GeneralSecurityException {
    if (this.keyType.equals("RSA")) {
      RSAKey rsaKey = (RSAKey) key;
      int foundKeySizeInBits = rsaKey.getModulus().bitLength();
      if (foundKeySizeInBits != this.keySizeInBits) {
        throw new GeneralSecurityException(
            String.format(
                "invalid RSA key size, want %d got %d", this.keySizeInBits, foundKeySizeInBits));
      }
    } else {
      ECKey ecKey = (ECKey) key;
      ECParameterSpec ecParams = ecKey.getParams();
      if (!EllipticCurves.isNistEcParameterSpec(ecParams)) {
        throw new GeneralSecurityException("unsupport EC spec: " + ecParams.toString());
      }

      int foundKeySizeInBits = EllipticCurves.fieldSizeInBits(ecParams.getCurve());
      if (foundKeySizeInBits != this.keySizeInBits) {
        throw new GeneralSecurityException(
            String.format(
                "invalid EC key size, want %d got %d", this.keySizeInBits, foundKeySizeInBits));
      }
    }
    return key;
  }
}
