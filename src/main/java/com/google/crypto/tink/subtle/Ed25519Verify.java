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

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.Ed25519;
import com.google.crypto.tink.internal.Field25519;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.internal.Ed25519VerifyJce;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Ed25519 verifying.
 *
 * <p>The first call to this function may take longer, because Ed25519Constants needs to be
 * initialized.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * // get the publicKey from the other party.
 * Ed25519Verify verifier = new Ed25519Verify(publicKey);
 * try {
 *   verifier.verify(signature, message);
 * } catch (GeneralSecurityException e) {
 *   // all the rest of security exceptions.
 * }
 * }</pre>
 *
 * @since 1.1.0
 */
@Immutable
public final class Ed25519Verify implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  public static final int PUBLIC_KEY_LEN = Field25519.FIELD_LEN;
  public static final int SIGNATURE_LEN = Field25519.FIELD_LEN * 2;

  private final Bytes publicKey;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @AccessesPartialKey
  public static PublicKeyVerify create(Ed25519PublicKey key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use Ed25519 in FIPS-mode.");
    }
    try {
      return Ed25519VerifyJce.create(key);
    } catch (GeneralSecurityException e) {
      // ignore.
    }
    return new Ed25519Verify(
        key.getPublicKeyBytes().toByteArray(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(Ed25519Parameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0]);
  }

  public Ed25519Verify(final byte[] publicKey) {
    this(publicKey, new byte[0], new byte[0]);
  }

  private Ed25519Verify(
      final byte[] publicKey, final byte[] outputPrefix, final byte[] messageSuffix) {
    if (!FIPS.isCompatible()) {
      // This should be a GenericSecurityException, however as external users rely on this
      // constructor not throwing a GenericSecurityException we use a runtime exception here
      // instead.
      throw new IllegalStateException(
          new GeneralSecurityException("Can not use Ed25519 in FIPS-mode."));
    }

    if (publicKey.length != PUBLIC_KEY_LEN) {
      throw new IllegalArgumentException(
          String.format("Given public key's length is not %s.", PUBLIC_KEY_LEN));
    }
    this.publicKey = Bytes.copyFrom(publicKey);
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
    Ed25519.init();
  }

  private void noPrefixVerify(byte[] signature, byte[] data) throws GeneralSecurityException {
    if (signature.length != SIGNATURE_LEN) {
      throw new GeneralSecurityException(
          String.format("The length of the signature is not %s.", SIGNATURE_LEN));
    }
    if (!Ed25519.verify(data, signature, publicKey.toByteArray())) {
      throw new GeneralSecurityException("Signature check failed.");
    }
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (outputPrefix.length == 0 && messageSuffix.length == 0) {
      noPrefixVerify(signature, data);
      return;
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    byte[] dataCopy = data;
    if (messageSuffix.length != 0) {
      dataCopy = com.google.crypto.tink.subtle.Bytes.concat(data, messageSuffix);
    }
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
    noPrefixVerify(signatureNoPrefix, dataCopy);
  }
}
