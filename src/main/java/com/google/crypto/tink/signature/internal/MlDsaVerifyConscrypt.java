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

package com.google.crypto.tink.signature.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaPublicKey;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;

/** ML-DSA verifying with Conscypt. */
@Immutable
public final class MlDsaVerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  static final int ML_DSA_65_SIG_LENGTH = 3309;
  static final String ML_DSA_65_ALGORITHM = "ML-DSA-65";

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable") // We do not change the private key
  private final PublicKey publicKey;

  private final String algorithm;
  private final int signatureLength;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private MlDsaVerifyConscrypt(
      byte[] outputPrefix,
      PublicKey publicKey,
      String algorithm,
      int signatureLength,
      Provider provider) {
    this.outputPrefix = outputPrefix;
    this.publicKey = publicKey;
    this.algorithm = algorithm;
    this.signatureLength = signatureLength;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static PublicKeyVerify create(MlDsaPublicKey mlDsaPublicKey)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ML-DSA in FIPS-mode, as BoringCrypto is not available.");
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }

    MlDsaInstance mlDsaInstance = mlDsaPublicKey.getParameters().getMlDsaInstance();
    if (mlDsaInstance != MlDsaInstance.ML_DSA_65) {
      throw new GeneralSecurityException("Only ML-DSA-65 currently supported");
    }

    // We ensured that the algorithm is ML-DSA-65
    PublicKey publicKey =
        KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider)
            .generatePublic(new RawKeySpec(mlDsaPublicKey.getSerializedPublicKey().toByteArray()));

    return new MlDsaVerifyConscrypt(
        mlDsaPublicKey.getOutputPrefix().toByteArray(),
        publicKey,
        ML_DSA_65_ALGORITHM,
        ML_DSA_65_SIG_LENGTH,
        provider);
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    if (signature.length != outputPrefix.length + signatureLength) {
      throw new GeneralSecurityException("Invalid signature length");
    }
    Signature verifier = Signature.getInstance(algorithm, provider);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (!verifier.verify(signature, outputPrefix.length, signatureLength)) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }

  /** Returns true if the Conscrypt is available and supports ML-DSA-65. */
  public static boolean isSupported() {
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider);
      Signature unusedSignature = Signature.getInstance(ML_DSA_65_ALGORITHM, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /** Representation of the raw keys for interoperability with Conscrypt. */
  public static final class RawKeySpec extends EncodedKeySpec {
    public RawKeySpec(byte[] encoded) {
      super(encoded);
    }

    @Override
    public String getFormat() {
      return "raw";
    }
  }
}
