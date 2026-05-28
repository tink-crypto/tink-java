// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static com.google.crypto.tink.subtle.Bytes.concat;
import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_XWING;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import org.conscrypt.HpkeContextSender;
import org.conscrypt.HpkeSuite;
import org.conscrypt.XdhKeySpec;

/** X-Wing HPKE encryption implementation using Conscrypt. */
public final class XWingHpkeConscryptEncrypt implements HybridEncrypt {
  private static final AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable")
  private final PublicKey recipientPublicKey;
  private final String hpkeSuiteName;
  @SuppressWarnings("Immutable")
  private final Provider conscryptProvider;
  private final int encapsulatedKeyLength;
  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  private static final byte[] emptyAssociatedData = new byte[0];

  /**
   * Returns a new instance of {@link HybridEncrypt} for HPKE that uses Conscrypt.
   */
  @AccessesPartialKey
  public static HybridEncrypt create(HpkePublicKey key)
      throws GeneralSecurityException {
    if (!isSupported()) {
      throw new GeneralSecurityException(
          "Can't use X-Wing, as we might be in FIPS mode, Conscrypt is not available, or Conscrypt"
              + " does not support X-Wing.");
    }

    Provider conscryptProvider = ConscryptUtil.providerOrNull();
    if (conscryptProvider == null) {
      throw new GeneralSecurityException("Can't use X-Wing as Conscrypt is not available");
    }

    HpkeParameters parameters = key.getParameters();
    String hpkeSuiteName = getHpkeSuiteName(parameters);
    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
    PublicKey recipientPublicKey =
        keyFactory.generatePublic(new XdhKeySpec(key.getPublicKeyBytes().toByteArray()));
    return new XWingHpkeConscryptEncrypt(
        recipientPublicKey,
        hpkeSuiteName,
        conscryptProvider,
        HpkeUtil.encodingSizeInBytes(parameters.getKemId()),
        key.getOutputPrefix());
  }

  private XWingHpkeConscryptEncrypt(
      PublicKey recipientPublicKey,
      String hpkeSuiteName,
      Provider conscryptProvider,
      int encapsulatedKeyLength,
      Bytes outputPrefix) {
    this.recipientPublicKey = recipientPublicKey;
    this.hpkeSuiteName = hpkeSuiteName;
    this.conscryptProvider = conscryptProvider;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
    this.outputPrefix = outputPrefix.toByteArray();
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    HpkeContextSender context = HpkeContextSender.getInstance(hpkeSuiteName, conscryptProvider);
    context.init(recipientPublicKey, contextInfo);

    byte[] encapsulatedKey = context.getEncapsulated();
    if (encapsulatedKey.length != encapsulatedKeyLength) {
      throw new IllegalStateException("Encapsulated key has wrong length");
    }
    byte[] ciphertext = context.seal(plaintext, emptyAssociatedData);
    return concat(outputPrefix, encapsulatedKey, ciphertext);
  }

  private static String getHpkeSuiteName(HpkeParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getKemId() != HpkeParameters.KemId.X_WING) {
      throw new GeneralSecurityException("Currently unsupported KEM: " + parameters.getKemId());
    }
    if (parameters.getKdfId() != HpkeParameters.KdfId.HKDF_SHA256) {
      throw new GeneralSecurityException("Currently unsupported KDF: " + parameters.getKdfId());
    }
    return new HpkeSuite(KEM_XWING, KDF_HKDF_SHA256, getAeadId(parameters.getAeadId())).name();
  }

  private static int getAeadId(HpkeParameters.AeadId aeadId) throws GeneralSecurityException {
    if (aeadId == HpkeParameters.AeadId.AES_128_GCM) {
      return AEAD_AES_128_GCM;
    }
    if (aeadId == HpkeParameters.AeadId.AES_256_GCM) {
      return AEAD_AES_256_GCM;
    }
    if (aeadId == HpkeParameters.AeadId.CHACHA20_POLY1305) {
      return AEAD_CHACHA20POLY1305;
    }
    throw new GeneralSecurityException("Unknown AEAD ID: " + aeadId);
  }

  /** Returns true if we're not in FIPS, and Conscrypt is available and supports X-Wing. */
  public static boolean isSupported() {
    if (!FIPS.isCompatible()) {
      return false;
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }

    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance("XWING", provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
