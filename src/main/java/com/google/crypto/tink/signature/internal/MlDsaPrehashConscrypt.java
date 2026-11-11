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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Objects;

/**
 * ML-DSA prehash computation with Conscrypt.
 *
 * <p>The prehash value of a message is {@code prehashPrefix || mu}, where {@code prehashPrefix} is
 * the key's {@link PrehashFormat} prefix and {@code mu} is the ML-DSA message representative of the
 * message with an empty context string (FIPS 204, Algorithm 7, line 6). It can be signed with
 * {@link MlDsaSignPrehashConscrypt}, and the resulting signature is verified with {@link
 * MlDsaVerifyConscrypt} and the original message.
 */
@Immutable
public final class MlDsaPrehashConscrypt implements Prehash {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  /** Conscrypt's {@code MessageDigest} computing SHAKE256 with a 512-bit (64-byte) output. */
  static final String SHAKE256_512_ALGORITHM = "SHAKE256-512";

  /** The length in bytes of an ML-DSA message representative mu. */
  static final int MU_LENGTH = 64;

  /** The length in bytes of a prehash value: the prehash prefix followed by mu. */
  static final int PREHASH_LENGTH = PrehashFormat.PREHASH_PREFIX_SIZE + MU_LENGTH;

  // The domain separator (0 for a pure, non-pre-hashed message) and the length of the empty context
  // string, which precede the message when computing mu (FIPS 204, Algorithm 2, line 10).
  private static final byte[] emptyContext = new byte[] {0, 0};

  @SuppressWarnings("Immutable") // We do not change the prehash prefix
  private final byte[] prehashPrefix;

  // The hash tr = SHAKE256-512(pk) of the raw public key (FIPS 204, Algorithm 6, line 9), which is
  // public and only depends on the key, so it is computed once.
  @SuppressWarnings("Immutable") // We do not change tr
  private final byte[] tr;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private MlDsaPrehashConscrypt(byte[] prehashPrefix, byte[] tr, Provider provider) {
    this.prehashPrefix = prehashPrefix;
    this.tr = tr;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static Prehash createWithProvider(MlDsaPublicKey mlDsaPublicKey, Provider provider)
      throws GeneralSecurityException {
    Objects.requireNonNull(provider, "provider must not be null");
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    // The prehash prefix identifies the key which has to sign the prehash value.
    Integer idRequirement = mlDsaPublicKey.getIdRequirementOrNull();
    if (idRequirement == null) {
      throw new GeneralSecurityException(
          "Prehash requires a key with an ID requirement, but the key has variant "
              + mlDsaPublicKey.getParameters().getVariant());
    }
    byte[] tr =
        MessageDigest.getInstance(SHAKE256_512_ALGORITHM, provider)
            .digest(mlDsaPublicKey.getSerializedPublicKey().toByteArray());
    return new MlDsaPrehashConscrypt(PrehashFormat.getPrehashPrefix(idRequirement), tr, provider);
  }

  @AccessesPartialKey
  public static Prehash create(MlDsaPublicKey mlDsaPublicKey) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    return createWithProvider(mlDsaPublicKey, provider);
  }

  /**
   * Returns true if we're not in FIPS, and Conscrypt is available and supports ML-DSA-{44, 65, 87}
   * and the SHAKE256-512 digest.
   */
  public static boolean isSupported() {
    if (!MlDsaVerifyConscrypt.isSupported()) {
      return false;
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      MessageDigest unused = MessageDigest.getInstance(SHAKE256_512_ALGORITHM, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Override
  public byte[] compute(final byte[] data) throws GeneralSecurityException {
    // mu = SHAKE256-512(tr || 0x00 || 0x00 || data), see FIPS 204, Algorithm 7, line 6.
    MessageDigest shake256 = MessageDigest.getInstance(SHAKE256_512_ALGORITHM, provider);
    shake256.update(tr);
    shake256.update(emptyContext);
    byte[] mu = shake256.digest(data);
    if (mu.length != MU_LENGTH) {
      throw new GeneralSecurityException("Unexpected mu length: " + mu.length);
    }
    return Bytes.concat(prehashPrefix, mu);
  }
}
