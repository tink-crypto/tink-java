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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

/** Ed25519 signing using the JCE. */
@Immutable
public final class Ed25519SignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  public static final int SECRET_KEY_LEN = 32;
  public static final int SIGNATURE_LEN = 32 * 2;
  private static final String ALGORITHM_NAME = "Ed25519";

  private static final byte[] ED25519_PKCS8_PREFIX =
      new byte[] {
        0x30, 0x2e, // Sequence: 46 bytes
        0x02, 0x01, 0x00, // Integer: 0 (version)
        0x30, 0x05, // Sequence: 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID: 1.3.101.112 (Ed25519)
        0x04, 0x22, 0x04, 0x20, // Octet string: 32 bytes
      };

  static byte[] pkcs8EncodePrivateKey(byte[] privateKey) throws GeneralSecurityException {
    if (privateKey.length != SECRET_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given private key's length is not %s", SECRET_KEY_LEN));
    }
    return Bytes.concat(ED25519_PKCS8_PREFIX, privateKey);
  }

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @SuppressWarnings("Immutable")
  private final PrivateKey privateKey;

  @AccessesPartialKey
  public static PublicKeySign create(Ed25519PrivateKey key) throws GeneralSecurityException {
    return new Ed25519SignJce(
        key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(Ed25519Parameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0]);
  }

  private Ed25519SignJce(
      final byte[] privateKey, final byte[] outputPrefix, final byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use Ed25519 in FIPS-mode.");
    }

    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;

    KeySpec spec = new PKCS8EncodedKeySpec(pkcs8EncodePrivateKey(privateKey));
    KeyFactory keyFactory = EngineFactory.KEY_FACTORY.getInstance(ALGORITHM_NAME);
    this.privateKey = keyFactory.generatePrivate(spec);
  }

  /** Constructs a Ed25519SignJce with the {@code privateKey}. */
  public Ed25519SignJce(final byte[] privateKey) throws GeneralSecurityException {
    this(privateKey, new byte[0], new byte[0]);
  }

  /** Returns true if the JCE supports Ed25519. */
  public static boolean isSupported() {
    try {
      KeyFactory unusedKeyFactory = EngineFactory.KEY_FACTORY.getInstance(ALGORITHM_NAME);
      Signature unusedSignature = EngineFactory.SIGNATURE.getInstance(ALGORITHM_NAME);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    Signature signer = EngineFactory.SIGNATURE.getInstance(ALGORITHM_NAME);
    signer.initSign(privateKey);
    signer.update(data);
    signer.update(messageSuffix);
    byte[] signature = signer.sign();
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}
