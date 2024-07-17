// Copyright 2024 Google LLC
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
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import javax.annotation.Nullable;

/** RSA SSA PSS verification with Conscrypt. */
@Immutable
public final class RsaSsaPssVerifyConscrypt implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final byte[] EMPTY = new byte[0];
  private static final byte[] LEGACY_MESSAGE_SUFFIX = new byte[] {0};

  // TODO(b/182987934) Move into a ConscryptUtil class.
  private static final String[] CONSCRYPT_PROVIDER_NAMES =
      new String[] {"GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt"};

  private static final String MGF_1 = "MGF1";

  private static final int TRAILER_FIELD_BC = 1;

  @Nullable
  private static Provider conscryptProviderOrNull() {
    if (Util.isAndroid() && Util.getAndroidApiLevel() <= 23) {
      // On Android API level 23 or lower, RSA SSA PSS is not supported.
      return null;
    }
    for (String providerName : CONSCRYPT_PROVIDER_NAMES) {
      Provider provider = Security.getProvider(providerName);
      if (provider != null) {
        return provider;
      }
    }
    return null;
  }

  // TODO(b/182987934) Move into a ConscryptUtil class.
  static final Provider CONSCRYPT = conscryptProviderOrNull();

  /** Returns true if Conscrypt is available and supports RSA SSA PSS. */
  public static boolean isSupported() {
    return CONSCRYPT != null;
  }

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final String signatureAlgorithm;

  @SuppressWarnings("Immutable")
  private final PSSParameterSpec parameterSpec;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  // These are the RSA SSA PSS algorithm names used by Conscrypt. See:
  // https://github.com/google/conscrypt/blob/master/CAPABILITIES.md#signature
  // Conscrypt does not support "RSASSA-PSS" used by OpenJDK,
  // see: https://github.com/C2SP/wycheproof/blob/master/doc/rsa.md
  static String getConscryptRsaSsaPssAlgo(RsaSsaPssParameters.HashType hash) {
    if (hash == RsaSsaPssParameters.HashType.SHA256) {
      return "SHA256withRSA/PSS";
    } else if (hash == RsaSsaPssParameters.HashType.SHA384) {
      return "SHA384withRSA/PSS";
    } else if (hash == RsaSsaPssParameters.HashType.SHA512) {
      return "SHA512withRSA/PSS";
    }
    throw new IllegalArgumentException("Unsupported hash: " + hash);
  }

  // The MD name value in PSSParameterSpec must match the hash type in the algorithm name.
  private static String getMdName(RsaSsaPssParameters.HashType sigHash) {
    if (sigHash == RsaSsaPssParameters.HashType.SHA256) {
      return "SHA-256";
    } else if (sigHash == RsaSsaPssParameters.HashType.SHA384) {
      return "SHA-384";
    } else if (sigHash == RsaSsaPssParameters.HashType.SHA512) {
      return "SHA-512";
    }
    throw new IllegalArgumentException("Unsupported MD hash: " + sigHash);
  }

  private static MGF1ParameterSpec getMgf1Hash(RsaSsaPssParameters.HashType mgf1Hash) {
    if (mgf1Hash == RsaSsaPssParameters.HashType.SHA256) {
      return MGF1ParameterSpec.SHA256;
    } else if (mgf1Hash == RsaSsaPssParameters.HashType.SHA384) {
      return MGF1ParameterSpec.SHA384;
    } else if (mgf1Hash == RsaSsaPssParameters.HashType.SHA512) {
      return MGF1ParameterSpec.SHA512;
    }
    throw new IllegalArgumentException("Unsupported MGF1 hash: " + mgf1Hash);
  }

  static PSSParameterSpec getPssParameterSpec(
      RsaSsaPssParameters.HashType sigHash, RsaSsaPssParameters.HashType mgf1Hash, int saltLength) {
    return new PSSParameterSpec(
        getMdName(sigHash), MGF_1, getMgf1Hash(mgf1Hash), saltLength, TRAILER_FIELD_BC);
  }

  private RsaSsaPssVerifyConscrypt(
      final RSAPublicKey pubKey,
      RsaSsaPssParameters.HashType sigHash,
      RsaSsaPssParameters.HashType mgf1Hash,
      int saltLength,
      byte[] outputPrefix,
      byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Cannot use RSA SSA PSS in FIPS-mode, as BoringCrypto module is not available.");
    }
    if (!sigHash.equals(mgf1Hash)) {
      throw new GeneralSecurityException("sigHash and mgf1Hash must be the same");
    }
    Validators.validateRsaModulusSize(pubKey.getModulus().bitLength());
    Validators.validateRsaPublicExponent(pubKey.getPublicExponent());
    this.publicKey = pubKey;
    this.signatureAlgorithm = getConscryptRsaSsaPssAlgo(sigHash);
    this.parameterSpec = getPssParameterSpec(sigHash, mgf1Hash, saltLength);
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  @AccessesPartialKey
  public static PublicKeyVerify create(RsaSsaPssPublicKey key) throws GeneralSecurityException {
    if (!isSupported()) {
      throw new GeneralSecurityException("RSA SSA PSS using Conscrypt is not supported.");
    }
    KeyFactory keyFactory = KeyFactory.getInstance("RSA", CONSCRYPT);
    RSAPublicKey publicKey =
        (RSAPublicKey)
            keyFactory.generatePublic(
                new RSAPublicKeySpec(key.getModulus(), key.getParameters().getPublicExponent()));
    RsaSsaPssParameters params = key.getParameters();
    return new RsaSsaPssVerifyConscrypt(
        publicKey,
        params.getSigHashType(),
        params.getMgf1HashType(),
        params.getSaltLengthBytes(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(RsaSsaPssParameters.Variant.LEGACY)
            ? LEGACY_MESSAGE_SUFFIX
            : EMPTY);
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    Signature verifier = Signature.getInstance(signatureAlgorithm, CONSCRYPT);
    verifier.initVerify(publicKey);
    verifier.setParameter(parameterSpec);
    verifier.update(data);
    if (messageSuffix.length > 0) {
      verifier.update(messageSuffix);
    }
    if (!verifier.verify(signature, outputPrefix.length, signature.length - outputPrefix.length)) {
      throw new GeneralSecurityException("signature verification failed");
    }
  }
}
