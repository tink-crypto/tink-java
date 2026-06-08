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

package com.google.crypto.tink.hybrid.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.crypto.hpke.Hpke;
import android.crypto.hpke.Message;
import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.internal.ConscryptUtil;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.EncodedKeySpec;
import java.util.Arrays;

/** X-Wing HPKE decryption implementation using Android HPKE API. */
public final class XWingHpkeConscryptDecrypt implements HybridDecrypt {

  private final PrivateKey recipientPrivateKey;
  private final String hpkeSuiteName;
  private final int encapsulatedKeyLength;
  private final byte[] outputPrefix;

  private static final byte[] emptyAssociatedData = new byte[0];
  private static final byte[] testWorkloadBytes = "Workload".getBytes(UTF_8);
  private static final byte[] testContextInfoBytes = "ContextInfo".getBytes(UTF_8);

  /** Returns a new instance of {@link HybridDecrypt} for HPKE that uses Conscrypt. */
  @AccessesPartialKey
  public static HybridDecrypt create(HpkePrivateKey privateKey) throws GeneralSecurityException {
    if (!XWingHpkeConscryptEncrypt.isSupported()) {
      throw new GeneralSecurityException(
          "Can't use X-Wing, as we might be in FIPS mode, Conscrypt is not available, or platform"
              + " does not support X-Wing.");
    }

    XWingHpkeConscryptDecrypt result = AndroidXWingHpkeDecryptImpl.create(privateKey);

    // Verify that the public key and the private key match by creating and verifying a dummy
    // encryption. It's suboptimal to do it this way, but at this time we prefer to not have our
    // own key derivation implementation, and some check is better than nothing.
    HybridEncrypt encrypt = XWingHpkeConscryptEncrypt.create(privateKey.getPublicKey());
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
      int encapsulatedKeyLength,
      byte[] outputPrefix) {
    this.recipientPrivateKey = recipientPrivateKey;
    this.hpkeSuiteName = hpkeSuiteName;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
    this.outputPrefix = outputPrefix;
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

    return AndroidXWingHpkeDecryptImpl.decrypt(
        recipientPrivateKey, hpkeSuiteName, encapsulatedKey, rawCiphertext, contextInfo);
  }

  private static String getHpkeSuiteName(HpkeParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getKemId() != HpkeParameters.KemId.X_WING) {
      throw new GeneralSecurityException("Currently unsupported KEM: " + parameters.getKemId());
    }
    if (parameters.getKdfId() != HpkeParameters.KdfId.HKDF_SHA256) {
      throw new GeneralSecurityException("Currently unsupported KDF: " + parameters.getKdfId());
    }
    if (parameters.getAeadId() == HpkeParameters.AeadId.AES_128_GCM) {
      return "XWING/HKDF_SHA256/AES_128_GCM";
    }
    if (parameters.getAeadId() == HpkeParameters.AeadId.AES_256_GCM) {
      return "XWING/HKDF_SHA256/AES_256_GCM";
    }
    if (parameters.getAeadId() == HpkeParameters.AeadId.CHACHA20_POLY1305) {
      return "XWING/HKDF_SHA256/CHACHA20POLY1305";
    }
    throw new GeneralSecurityException("Unknown AEAD ID: " + parameters.getAeadId());
  }

  // Nested class to isolate Android HPKE API dependencies. It's a way to prevent class
  // verification failures on older devices by leveraging lazy class verification.
  // Note that it does not allow us to compile this code against API level below 37.
  // Instead, what it ensures is that our code (compiled against the API level 37+) will be able
  // to run on a device with a lower API level and handle the absence of the required APIs
  // gracefully.
  @SuppressWarnings("NewApi")
  private static class AndroidXWingHpkeDecryptImpl {
    @AccessesPartialKey
    static XWingHpkeConscryptDecrypt create(HpkePrivateKey privateKey)
        throws GeneralSecurityException {
      Provider conscryptProvider = ConscryptUtil.providerOrNull();
      if (conscryptProvider == null) {
        throw new GeneralSecurityException("Can't use X-Wing as Conscrypt is not available");
      }

      HpkeParameters parameters = privateKey.getParameters();
      String hpkeSuiteName = getHpkeSuiteName(parameters);
      KeyFactory keyFactory = KeyFactory.getInstance("XWING", conscryptProvider);
      PrivateKey recipientPrivateKey =
          keyFactory.generatePrivate(
              new EncodedKeySpec(
                  privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())) {
                @Override
                public String getFormat() {
                  return "raw";
                }
              });

      return new XWingHpkeConscryptDecrypt(
          recipientPrivateKey,
          hpkeSuiteName,
          HpkeUtil.encodingSizeInBytes(parameters.getKemId()),
          privateKey.getOutputPrefix().toByteArray());
    }

    static byte[] decrypt(
        PrivateKey recipientPrivateKey,
        String hpkeSuiteName,
        byte[] encapsulatedKey,
        byte[] rawCiphertext,
        byte[] contextInfo)
        throws GeneralSecurityException {
      Hpke hpke = Hpke.getInstance(hpkeSuiteName);
      Message message = new Message(encapsulatedKey, rawCiphertext);
      return hpke.open(recipientPrivateKey, contextInfo, message, emptyAssociatedData);
    }
  }
}
