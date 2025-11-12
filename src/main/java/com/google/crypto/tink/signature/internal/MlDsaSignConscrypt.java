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

import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_65_ALGORITHM;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_65_SIG_LENGTH;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.MlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.MlDsaPrivateKey;
import com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.RawKeySpec;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

/** ML-DSA signing with Conscypt. */
@Immutable
public final class MlDsaSignConscrypt implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final String TEST_WORKLOAD = "test workload";

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;
  @SuppressWarnings("Immutable") // We do not change the private key
  private final PrivateKey privateKey;
  private final String algorithm;
  private final int signatureLength;
  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private MlDsaSignConscrypt(
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider) {
    this.outputPrefix = outputPrefix;
    this.privateKey = privateKey;
    this.algorithm = algorithm;
    this.signatureLength = signatureLength;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static PublicKeySign create(MlDsaPrivateKey mlDsaPrivateKey)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    MlDsaInstance mlDsaInstance = mlDsaPrivateKey.getPublicKey().getParameters().getMlDsaInstance();
    if (mlDsaInstance != MlDsaInstance.ML_DSA_65) {
      throw new GeneralSecurityException("Only ML-DSA-65 currently supported");
    }
    // We ensured that the algorithm is ML-DSA-65
    PrivateKey privateKey =
        KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider)
            .generatePrivate(
                new RawKeySpec(
                    mlDsaPrivateKey.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get())));

    // Verify that the public key and the private key match by creating and verifying a dummy
    // signature. This is subomptimal to do it this way, but at this time we prefer to not have our
    // own key derivation implementation, and some check is better than nothing.
    byte[] testSignature =
        signInternal(
            TEST_WORKLOAD.getBytes(UTF_8),
            mlDsaPrivateKey.getOutputPrefix().toByteArray(),
            privateKey,
            ML_DSA_65_ALGORITHM,
            ML_DSA_65_SIG_LENGTH,
            provider);
    MlDsaVerifyConscrypt verifier =
        (MlDsaVerifyConscrypt) MlDsaVerifyConscrypt.create(mlDsaPrivateKey.getPublicKey());
    verifier.verify(testSignature, TEST_WORKLOAD.getBytes(UTF_8));

    // If verified successfully, proceed with the primitive creation.
    return new MlDsaSignConscrypt(
        mlDsaPrivateKey.getOutputPrefix().toByteArray(),
        privateKey,
        ML_DSA_65_ALGORITHM,
        ML_DSA_65_SIG_LENGTH,
        provider);
  }

  /** Returns true if the Conscrypt is available and supports ML-DSA-65. */
  public static boolean isSupported() {
    return MlDsaVerifyConscrypt.isSupported();
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    return signInternal(data, outputPrefix, privateKey, algorithm, signatureLength, provider);
  }

  private static byte[] signInternal(
      byte[] data,
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider)
      throws GeneralSecurityException {
    Signature signer = Signature.getInstance(algorithm, provider);
    signer.initSign(privateKey);
    signer.update(data);
    byte[] signature = new byte[outputPrefix.length + signatureLength];
    if (outputPrefix.length > 0) {
      System.arraycopy(outputPrefix, 0, signature, 0, outputPrefix.length);
    }
    // Use this interface instead of plain sign() to avoid an extra copy of 3MB of signature.
    // Resets the Signature object into its initial initialized state.
    signer.sign(signature, outputPrefix.length, signatureLength);
    return signature;
  }
}
