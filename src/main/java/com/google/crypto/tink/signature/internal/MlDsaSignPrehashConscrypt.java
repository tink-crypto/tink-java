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

import static com.google.crypto.tink.internal.Util.isPrefix;
import static com.google.crypto.tink.signature.internal.MlDsaPrehashConscrypt.MU_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaPrehashConscrypt.PREHASH_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_44_ALGORITHM;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_44_SIG_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_65_ALGORITHM;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_65_SIG_LENGTH;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_87_ALGORITHM;
import static com.google.crypto.tink.signature.internal.MlDsaVerifyConscrypt.ML_DSA_87_SIG_LENGTH;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.SignPrehash;
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

/**
 * ML-DSA prehash signing with Conscrypt ("external mu" ML-DSA).
 *
 * <p>Signs prehash values computed by {@link MlDsaPrehashConscrypt} with the public key of the same
 * key pair, i.e. {@code prehashPrefix || mu} where {@code prehashPrefix} is the key's {@link
 * PrehashFormat} prefix and {@code mu} is the ML-DSA message representative of the message. The
 * signature is a regular ML-DSA signature of the message, so it is verified with {@link
 * MlDsaVerifyConscrypt} and the original message.
 */
@Immutable
public final class MlDsaSignPrehashConscrypt implements SignPrehash {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  // Conscrypt's Signatures signing a precomputed 64-byte message representative mu.
  static final String EXTERNAL_MU_ML_DSA_44_ALGORITHM = "EXTERNAL-MU-ML-DSA-44";
  static final String EXTERNAL_MU_ML_DSA_65_ALGORITHM = "EXTERNAL-MU-ML-DSA-65";
  static final String EXTERNAL_MU_ML_DSA_87_ALGORITHM = "EXTERNAL-MU-ML-DSA-87";

  private static final String TEST_WORKLOAD = "test workload";

  @SuppressWarnings("Immutable") // We do not change the prehash prefix
  private final byte[] prehashPrefix;

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable") // We do not change the private key
  private final PrivateKey privateKey;

  private final String algorithm;
  private final int signatureLength;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  private MlDsaSignPrehashConscrypt(
      byte[] prehashPrefix,
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider) {
    this.prehashPrefix = prehashPrefix;
    this.outputPrefix = outputPrefix;
    this.privateKey = privateKey;
    this.algorithm = algorithm;
    this.signatureLength = signatureLength;
    this.provider = provider;
  }

  @AccessesPartialKey
  public static SignPrehash create(MlDsaPrivateKey mlDsaPrivateKey)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ML-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    // The prehash prefix identifies the key which has to sign the prehash value.
    Integer idRequirement = mlDsaPrivateKey.getPublicKey().getIdRequirementOrNull();
    if (idRequirement == null) {
      throw new GeneralSecurityException(
          "SignPrehash requires a key with an ID requirement, but the key has variant "
              + mlDsaPrivateKey.getParameters().getVariant());
    }
    MlDsaInstance mlDsaInstance = mlDsaPrivateKey.getParameters().getMlDsaInstance();
    byte[] privateSeed =
        mlDsaPrivateKey.getPrivateSeed().toByteArray(InsecureSecretKeyAccess.get());
    PrivateKey privateKey;
    String algorithm;
    int signatureLength;
    if (mlDsaInstance == MlDsaInstance.ML_DSA_44) {
      algorithm = EXTERNAL_MU_ML_DSA_44_ALGORITHM;
      signatureLength = ML_DSA_44_SIG_LENGTH;
      privateKey =
          KeyFactory.getInstance(ML_DSA_44_ALGORITHM, provider)
              .generatePrivate(new RawKeySpec(privateSeed));
    } else if (mlDsaInstance == MlDsaInstance.ML_DSA_65) {
      algorithm = EXTERNAL_MU_ML_DSA_65_ALGORITHM;
      signatureLength = ML_DSA_65_SIG_LENGTH;
      privateKey =
          KeyFactory.getInstance(ML_DSA_65_ALGORITHM, provider)
              .generatePrivate(new RawKeySpec(privateSeed));
    } else if (mlDsaInstance == MlDsaInstance.ML_DSA_87) {
      algorithm = EXTERNAL_MU_ML_DSA_87_ALGORITHM;
      signatureLength = ML_DSA_87_SIG_LENGTH;
      privateKey =
          KeyFactory.getInstance(ML_DSA_87_ALGORITHM, provider)
              .generatePrivate(new RawKeySpec(privateSeed));
    } else {
      throw new GeneralSecurityException("Unsupported ML-DSA instance: " + mlDsaInstance);
    }
    byte[] prehashPrefix = PrehashFormat.getPrehashPrefix(idRequirement);
    byte[] outputPrefix = mlDsaPrivateKey.getOutputPrefix().toByteArray();

    // Verify that the public key and the private key match by signing the prehash value of a test
    // message and verifying the signature. This is suboptimal to do it this way, but at this time
    // we prefer to not have our own key derivation implementation, and some check is better than
    // nothing.
    Prehash prehash =
        MlDsaPrehashConscrypt.createWithProvider(mlDsaPrivateKey.getPublicKey(), provider);
    byte[] testSignature =
        signInternal(
            prehash.compute(TEST_WORKLOAD.getBytes(UTF_8)),
            prehashPrefix,
            outputPrefix,
            privateKey,
            algorithm,
            signatureLength,
            provider);
    PublicKeyVerify verifier =
        MlDsaVerifyConscrypt.createWithProvider(mlDsaPrivateKey.getPublicKey(), provider);
    verifier.verify(testSignature, TEST_WORKLOAD.getBytes(UTF_8));

    // If verified successfully, proceed with the primitive creation.
    return new MlDsaSignPrehashConscrypt(
        prehashPrefix, outputPrefix, privateKey, algorithm, signatureLength, provider);
  }

  /**
   * Returns true if we're not in FIPS, and Conscrypt is available and supports "external mu"
   * ML-DSA-{44, 65, 87} signing as well as the prehash computation.
   */
  public static boolean isSupported() {
    if (!MlDsaPrehashConscrypt.isSupported()) {
      return false;
    }
    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }
    try {
      Signature unusedSignature44 =
          Signature.getInstance(EXTERNAL_MU_ML_DSA_44_ALGORITHM, provider);
      Signature unusedSignature65 =
          Signature.getInstance(EXTERNAL_MU_ML_DSA_65_ALGORITHM, provider);
      Signature unusedSignature87 =
          Signature.getInstance(EXTERNAL_MU_ML_DSA_87_ALGORITHM, provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  @Override
  public byte[] sign(final byte[] prehash) throws GeneralSecurityException {
    return signInternal(
        prehash, prehashPrefix, outputPrefix, privateKey, algorithm, signatureLength, provider);
  }

  private static byte[] signInternal(
      byte[] prehash,
      byte[] prehashPrefix,
      byte[] outputPrefix,
      PrivateKey privateKey,
      String algorithm,
      int signatureLength,
      Provider provider)
      throws GeneralSecurityException {
    if (prehash.length != PREHASH_LENGTH) {
      throw new GeneralSecurityException(
          "Invalid prehash length: expected " + PREHASH_LENGTH + ", got " + prehash.length);
    }
    if (!isPrefix(prehashPrefix, prehash)) {
      throw new GeneralSecurityException("Invalid prehash (prehash prefix mismatch)");
    }
    Signature signer = Signature.getInstance(algorithm, provider);
    signer.initSign(privateKey);
    signer.update(prehash, prehashPrefix.length, MU_LENGTH);
    byte[] signature = new byte[outputPrefix.length + signatureLength];
    if (outputPrefix.length > 0) {
      System.arraycopy(outputPrefix, 0, signature, 0, outputPrefix.length);
    }
    // Use this interface instead of plain sign() to avoid an extra copy of 3KB of signature.
    // Resets the Signature object into its initial initialized state.
    signer.sign(signature, outputPrefix.length, signatureLength);
    return signature;
  }
}
