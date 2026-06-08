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

import static com.google.crypto.tink.internal.Util.UTF_8;
import static com.google.crypto.tink.internal.Util.isPrefix;
import static org.conscrypt.HpkeSuite.AEAD_AES_128_GCM;
import static org.conscrypt.HpkeSuite.AEAD_AES_256_GCM;
import static org.conscrypt.HpkeSuite.AEAD_CHACHA20POLY1305;
import static org.conscrypt.HpkeSuite.KDF_HKDF_SHA256;
import static org.conscrypt.HpkeSuite.KEM_XWING;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Arrays;
import org.conscrypt.HpkeContextRecipient;
import org.conscrypt.HpkeSuite;
import org.conscrypt.XdhKeySpec;

/** X-Wing HPKE decryption implementation using Conscrypt. */
public final class XWingHpkeConscryptDecrypt implements HybridDecrypt {

  @SuppressWarnings("Immutable")
  private final PrivateKey recipientPrivateKey;
  private final String hpkeSuiteName;
  @SuppressWarnings("Immutable")
  private final Provider conscryptProvider;
  private final int encapsulatedKeyLength;
  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  private static final byte[] testWorkloadBytes = "test workload".getBytes(UTF_8);
  private static final byte[] testContextInfoBytes = "test context info".getBytes(UTF_8);
  private static final byte[] emptyAssociatedData = new byte[0];

  /**
   * Returns a new instance of {@link HybridDecrypt} for HPKE that uses Conscrypt.
   */
  @AccessesPartialKey
  public static HybridDecrypt create(HpkePrivateKey privateKey)
      throws GeneralSecurityException {
    if (!XWingHpkeConscryptEncrypt.isSupported()) {
      throw new GeneralSecurityException(
          "Can't use X-Wing, as we might be in FIPS mode, Conscrypt is not available, or Conscrypt"
              + " does not support X-Wing.");
    }

    Provider conscryptProvider = ConscryptUtil.providerOrNull();
    if (conscryptProvider == null) {
      throw new GeneralSecurityException("Can't use X-Wing as Conscrypt is not available");
    }

    HpkeParameters parameters = privateKey.getParameters();
    String hpkeSuiteName = getHpkeSuiteName(parameters);
    KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
    PrivateKey recipientPrivateKey =
        keyFactory.generatePrivate(
            new XdhKeySpec(
                privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    HybridDecrypt result =
        new XWingHpkeConscryptDecrypt(
            recipientPrivateKey,
            hpkeSuiteName,
            conscryptProvider,
            HpkeUtil.encodingSizeInBytes(parameters.getKemId()),
            privateKey.getOutputPrefix());

    // Verify that the public key and the private key match by creating and verifying a dummy
    // encryption. It's suboptimal to do it this way, but at this time we prefer to not have our
    // own key derivation implementation, and some check is better than nothing.
    HybridEncrypt encrypt =
        XWingHpkeConscryptEncrypt.create(privateKey.getPublicKey());
    byte[] ciphertext = encrypt.encrypt(testWorkloadBytes, testContextInfoBytes);
    byte[] plaintext = result.decrypt(ciphertext, testContextInfoBytes);
    if (!Arrays.equals(plaintext, testWorkloadBytes)) {
      throw new GeneralSecurityException(
          "Public key and private key do not match, cannot create HybridDecrypt instance");
    }

    return result;
  }

  private XWingHpkeConscryptDecrypt(
      PrivateKey recipientPrivateKey,
      String hpkeSuiteName,
      Provider conscryptProvider,
      int encapsulatedKeyLength,
      Bytes outputPrefix) {
    this.recipientPrivateKey = recipientPrivateKey;
    this.hpkeSuiteName = hpkeSuiteName;
    this.conscryptProvider = conscryptProvider;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
    this.outputPrefix = outputPrefix.toByteArray();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    int prefixAndHeaderLength = outputPrefix.length + encapsulatedKeyLength;
    if (ciphertext.length < prefixAndHeaderLength) {
      throw new GeneralSecurityException("Ciphertext is too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Invalid ciphertext (output prefix mismatch)");
    }
    byte[] encapsulatedKey =
        Arrays.copyOfRange(ciphertext, outputPrefix.length, prefixAndHeaderLength);
    byte[] rawCiphertext = Arrays.copyOfRange(ciphertext, prefixAndHeaderLength, ciphertext.length);

    HpkeContextRecipient context =
        HpkeContextRecipient.getInstance(hpkeSuiteName, conscryptProvider);
    context.init(encapsulatedKey, recipientPrivateKey, contextInfo);
    return context.open(rawCiphertext, emptyAssociatedData);
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
}
