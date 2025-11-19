// Copyright 2025 Google LLC
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Private key for ML-DSA-65.
 */
public class MlDsaPrivateKey extends SignaturePrivateKey {

  private static final int MLDSA_SEED_BYTES = 32;

  private final MlDsaPublicKey publicKey;
  private final SecretBytes privateSeed;

  private MlDsaPrivateKey(MlDsaPublicKey publicKey, SecretBytes privateSeed) {
    this.publicKey = publicKey;
    this.privateSeed = privateSeed;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public static MlDsaPrivateKey createWithoutVerification(MlDsaPublicKey mlDsaPublicKey, SecretBytes privateSeed)
      throws GeneralSecurityException {
    if (privateSeed.size() != MLDSA_SEED_BYTES) {
      throw new GeneralSecurityException("Incorrect private seed size for ML-DSA");
    }
    if (((MlDsaParameters) mlDsaPublicKey.getParameters()).getMlDsaInstance()
        != MlDsaInstance.ML_DSA_65) {
      throw new GeneralSecurityException(
          "Unknown ML-DSA instance; only ML-DSA-65 is currently supported");
    }
    // WARNING: currently NO VERIFICATION checks are performed since Conscrypt doesn't expose the
    // necessary functionality (public-from-private key derivation is not a part of the
    // standard JCE API), while implementing it directly in Tink is undesirable due to complexity,
    // maintenance cost, and introducing dependencies into the Key classes. It's the same dependency
    // reason that prevents us from just taking an artificial workload and trying to sign/verify it,
    // apart from the potential side effects of doing so and some correctness concerns (the latter
    // more as a general concern rather than being directly applicable here).
    // Using the BoringSSL functions would be possible via JNI, however Tink currently doesn't use
    // JNI, so introducing it would be a considerable cost and a separate effort.
    return new MlDsaPrivateKey(mlDsaPublicKey, privateSeed);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getPrivateSeed() {
    return privateSeed;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof MlDsaPrivateKey)) {
      return false;
    }
    MlDsaPrivateKey that = (MlDsaPrivateKey) o;
    return that.publicKey.equalsKey(publicKey) && privateSeed.equalsSecretBytes(that.privateSeed);
  }

  @Override
  public MlDsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public MlDsaPublicKey getPublicKey() {
    return publicKey;
  }
}
