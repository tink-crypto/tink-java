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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/** Ed25519 verifying using the JCE.
 *
 * <p>Can currently only be used when the Conscrypt provider is available.
 */
@Immutable
public final class Ed25519VerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final int PUBLIC_KEY_LEN = 32;
  private static final int SIGNATURE_LEN = 32 * 2;
  private static final String ALGORITHM_NAME = "Ed25519";

  private static final byte[] ed25519X509Prefix =
      new byte[] {
        0x30, 0x2a, // Sequence: 42 bytes
        0x30, 0x05, // Sequence: 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID id-Ed25519
        0x03, 0x21, 0x00, // Bit string: 256 bits
      };

  static byte[] x509EncodePublicKey(byte[] publicKey) throws GeneralSecurityException {
    if (publicKey.length != PUBLIC_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given public key's length is not %s.", PUBLIC_KEY_LEN));
    }
    return Bytes.concat(ed25519X509Prefix, publicKey);
  }

  @SuppressWarnings("Immutable")
  private final PublicKey publicKey;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @SuppressWarnings("Immutable")
  private final Provider provider;

  static Provider conscryptProvider() {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new UnsupportedOperationException("Ed25519VerifyJce requires the Conscrypt provider.");
    }
    return provider;
  }

  @AccessesPartialKey
  public static PublicKeyVerify create(Ed25519PublicKey key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use Ed25519 in FIPS-mode.");
    }
    return new Ed25519VerifyJce(
        key.getPublicKeyBytes().toByteArray(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(Ed25519Parameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0],
        conscryptProvider());
  }

  Ed25519VerifyJce(final byte[] publicKey) throws GeneralSecurityException {
    this(publicKey, new byte[0], new byte[0], conscryptProvider());
  }

  private Ed25519VerifyJce(
      final byte[] publicKey,
      final byte[] outputPrefix,
      final byte[] messageSuffix,
      final Provider provider)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use Ed25519 in FIPS-mode.");
    }
    // We prefer not to use EdECPublicKeySpec, because it would require to encode the public key
    // as (boolean xOdd, BigInteger Y) tuple, which would be more cumbersome to implement than
    // x509EncodePublicKey.
    // Also, EdECPublicKeySpec is only available since Java 15 and Android API Level 33.
    KeySpec spec = new X509EncodedKeySpec(x509EncodePublicKey(publicKey));
    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME, provider);
    this.publicKey = keyFactory.generatePublic(spec);

    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
    this.provider = provider;
  }

  /** Returns true if the JCE supports Ed25519. */
  public static boolean isSupported() {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance(ALGORITHM_NAME, provider);
      Signature unusedSignature = Signature.getInstance(ALGORITHM_NAME, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (signature.length != outputPrefix.length + SIGNATURE_LEN) {
      throw new GeneralSecurityException(
          String.format("Invalid signature length: %s", SIGNATURE_LEN));
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    Signature verifier = Signature.getInstance(ALGORITHM_NAME, provider);
    verifier.initVerify(publicKey);
    verifier.update(data);
    verifier.update(messageSuffix);
    boolean verified;
    try {
      verified =
          verifier.verify(
              signature, /* offset= */ outputPrefix.length, /* length= */ SIGNATURE_LEN);
    } catch (RuntimeException ex) {
      // It is not clear if this ever throws a RuntimeException. Some implementations
      // might, so we catch it just in case.
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Signature check failed.");
    }
  }
}
