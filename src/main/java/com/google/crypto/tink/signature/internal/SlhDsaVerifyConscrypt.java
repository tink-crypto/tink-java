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
import com.google.crypto.tink.config.internal.TinkFipsUtil.AlgorithmFipsCompatibility;
import com.google.crypto.tink.internal.ConscryptUtil;
import com.google.crypto.tink.signature.SlhDsaParameters;
import com.google.crypto.tink.signature.SlhDsaParameters.HashType;
import com.google.crypto.tink.signature.SlhDsaParameters.SignatureType;
import com.google.crypto.tink.signature.SlhDsaPublicKey;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;

/** SLH-DSA verification with Conscypt. */
@Immutable
public class SlhDsaVerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  static final int SLH_DSA_SHA2_128S_SIG_LENGTH = 7856;
  static final String SLH_DSA_SHA2_128S_ALGORITHM = "SLH-DSA-SHA2-128S";

  @SuppressWarnings("Immutable") // We do not change the output prefix
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable") // We do not change the private key
  private final PublicKey publicKey;

  private final String algorithm;
  private final int signatureLength;

  @SuppressWarnings("Immutable") // We do not change the provider
  private final Provider provider;

  public SlhDsaVerifyConscrypt(
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
  public static PublicKeyVerify createWithProvider(SlhDsaPublicKey slhDsaPublicKey, Provider provider)
      throws GeneralSecurityException {
    if (provider == null) {
      throw new NullPointerException("provider must not be null");
    }
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use SLH-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }
    SlhDsaParameters parameters = slhDsaPublicKey.getParameters();
    if (parameters.getPrivateKeySize() != SlhDsaParameters.SLH_DSA_128_PRIVATE_KEY_SIZE_BYTES
        || parameters.getHashType() != HashType.SHA2
        || parameters.getSignatureType() != SignatureType.SMALL_SIGNATURE) {
      throw new GeneralSecurityException("Unsupported SLH-DSA parameters");
    }

    PublicKey publicKey =
        KeyFactory.getInstance(SLH_DSA_SHA2_128S_ALGORITHM, provider)
            .generatePublic(new RawKeySpec(slhDsaPublicKey.getSerializedPublicKey().toByteArray()));

    return new SlhDsaVerifyConscrypt(
        slhDsaPublicKey.getOutputPrefix().toByteArray(),
        publicKey,
        SLH_DSA_SHA2_128S_ALGORITHM,
        SLH_DSA_SHA2_128S_SIG_LENGTH,
        provider);
  }

  @AccessesPartialKey
  public static PublicKeyVerify create(SlhDsaPublicKey slhDsaPublicKey)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use SLH-DSA in FIPS-mode, as it is not yet certified in Conscrypt.");
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      throw new GeneralSecurityException("Obtaining Conscrypt provider failed");
    }
    return createWithProvider(slhDsaPublicKey, provider);
  }

  @Override
  public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
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

  /** Returns true if we're not in FIPS, and Conscrypt is available and supports SLH-DSA-SHA2-128S. */
  public static boolean isSupported() {
    if (!FIPS.isCompatible()) {
      return false;
    }

    Provider provider = ConscryptUtil.providerOrNull();
    if (provider == null) {
      return false;
    }

    try {
      KeyFactory unusedKeyFactory = KeyFactory.getInstance(SLH_DSA_SHA2_128S_ALGORITHM, provider);
      Signature unusedSignature = Signature.getInstance(SLH_DSA_SHA2_128S_ALGORITHM, provider);
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
