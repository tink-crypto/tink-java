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
import com.google.crypto.tink.internal.Asn1Util;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import java.security.GeneralSecurityException;

/** Utility methods for Composite ML-DSA signatures. Requires Conscrypt. */
public final class CompositeMlDsaUtil {

  private static final String MLDSA44_ED25519_SHA512 = "MLDSA44-Ed25519-SHA512";
  private static final String MLDSA44_ECDSA_P256_SHA256 = "MLDSA44-ECDSA-P256-SHA256";
  private static final String MLDSA44_RSA2048_PSS_SHA256 = "MLDSA44-RSA2048-PSS-SHA256";
  private static final String MLDSA44_RSA2048_PKCS15_SHA256 = "MLDSA44-RSA2048-PKCS15-SHA256";
  private static final String MLDSA65_ED25519_SHA512 = "MLDSA65-Ed25519-SHA512";
  private static final String MLDSA65_ECDSA_P256_SHA512 = "MLDSA65-ECDSA-P256-SHA512";
  private static final String MLDSA65_ECDSA_P384_SHA512 = "MLDSA65-ECDSA-P384-SHA512";
  private static final String MLDSA65_RSA3072_PSS_SHA512 = "MLDSA65-RSA3072-PSS-SHA512";
  private static final String MLDSA65_RSA4096_PSS_SHA512 = "MLDSA65-RSA4096-PSS-SHA512";
  private static final String MLDSA65_RSA3072_PKCS15_SHA512 = "MLDSA65-RSA3072-PKCS15-SHA512";
  private static final String MLDSA65_RSA4096_PKCS15_SHA512 = "MLDSA65-RSA4096-PKCS15-SHA512";
  private static final String MLDSA87_ECDSA_P384_SHA512 = "MLDSA87-ECDSA-P384-SHA512";
  private static final String MLDSA87_ECDSA_P521_SHA512 = "MLDSA87-ECDSA-P521-SHA512";
  private static final String MLDSA87_RSA3072_PSS_SHA512 = "MLDSA87-RSA3072-PSS-SHA512";
  private static final String MLDSA87_RSA4096_PSS_SHA512 = "MLDSA87-RSA4096-PSS-SHA512";

  private CompositeMlDsaUtil() {}

  public static String getAlgorithmName(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.MlDsaInstance mlDsaInstance = parameters.getMlDsaInstance();
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_44)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.ED25519)) {
        return MLDSA44_ED25519_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.ECDSA_P256)) {
        return MLDSA44_ECDSA_P256_SHA256;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)) {
        return MLDSA44_RSA2048_PSS_SHA256;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PKCS1)) {
        return MLDSA44_RSA2048_PKCS15_SHA256;
      } else {
        throw new GeneralSecurityException(
            "Unsupported classical algorithm for ML-DSA-44: " + classicalAlgorithm);
      }
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_65)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.ED25519)) {
        return MLDSA65_ED25519_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.ECDSA_P256)) {
        return MLDSA65_ECDSA_P256_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.ECDSA_P384)) {
        return MLDSA65_ECDSA_P384_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
        return MLDSA65_RSA3072_PSS_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
        return MLDSA65_RSA4096_PSS_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PKCS1)) {
        return MLDSA65_RSA3072_PKCS15_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
        return MLDSA65_RSA4096_PKCS15_SHA512;
      } else {
        throw new GeneralSecurityException(
            "Unsupported classical algorithm for ML-DSA-65: " + classicalAlgorithm);
      }
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_87)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.ECDSA_P384)) {
        return MLDSA87_ECDSA_P384_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.ECDSA_P521)) {
        return MLDSA87_ECDSA_P521_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
        return MLDSA87_RSA3072_PSS_SHA512;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
        return MLDSA87_RSA4096_PSS_SHA512;
      } else {
        throw new GeneralSecurityException(
            "Unsupported classical algorithm for ML-DSA-87: " + classicalAlgorithm);
      }
    } else {
      throw new GeneralSecurityException("Unsupported ML-DSA instance: " + mlDsaInstance);
    }
  }

  public static int getRsaSaltLengthBytes(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
      return 32;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
      return 48;
    } else {
      throw new GeneralSecurityException(
          "Unsupported RSA algorithm for composite signatures: " + classicalAlgorithm);
    }
  }

  public static RsaSsaPssParameters.HashType getRsaMgf1HashType(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
      return RsaSsaPssParameters.HashType.SHA256;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
      return RsaSsaPssParameters.HashType.SHA384;
    } else {
      throw new GeneralSecurityException(
          "Unsupported RSA algorithm for composite signatures: " + classicalAlgorithm);
    }
  }

  public static RsaSsaPssParameters.HashType getRsaPssSigHashType(
      CompositeMlDsaParameters parameters) throws GeneralSecurityException {
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
      return RsaSsaPssParameters.HashType.SHA256;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
      return RsaSsaPssParameters.HashType.SHA384;
    } else {
      throw new GeneralSecurityException(
          "Unsupported RSA algorithm for composite signatures: " + classicalAlgorithm);
    }
  }

  public static RsaSsaPkcs1Parameters.HashType getRsaPkcs1SigHashType(
      CompositeMlDsaParameters parameters) throws GeneralSecurityException {
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PKCS1)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PKCS1)) {
      return RsaSsaPkcs1Parameters.HashType.SHA256;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      return RsaSsaPkcs1Parameters.HashType.SHA384;
    } else {
      throw new GeneralSecurityException(
          "Unsupported RSA algorithm for composite signatures: " + classicalAlgorithm);
    }
  }

  public static int getRsaModulusSizeBits(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PKCS1)) {
      return 2048;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PKCS1)) {
      return 3072;
    } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)
        || classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      return 4096;
    } else {
      throw new GeneralSecurityException(
          "Unsupported RSA algorithm for composite signatures: " + classicalAlgorithm);
    }
  }

  @AccessesPartialKey
  public static RsaSsaPssPrivateKey pkcs1RsaKeyToRsaSsaPssPrivateKey(
      byte[] pkcs1Key, CompositeMlDsaParameters compositeParameters)
      throws GeneralSecurityException {
    if (!compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PSS)
        && !compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PSS)
        && !compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PSS)) {
      throw new GeneralSecurityException(
          "Not an RSA-PSS classical algorithm: " + compositeParameters.getClassicalAlgorithm());
    }

    RsaSsaPssParameters rsaParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(getRsaModulusSizeBits(compositeParameters))
            // This might not technically be true, but we'll verify in Asn1Util call below.
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setMgf1HashType(getRsaMgf1HashType(compositeParameters))
            .setSigHashType(getRsaPssSigHashType(compositeParameters))
            .setSaltLengthBytes(getRsaSaltLengthBytes(compositeParameters))
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    return Asn1Util.pkcs1RsaKeyToRsaSsaPssPrivateKey(pkcs1Key, rsaParameters);
  }

  @AccessesPartialKey
  public static RsaSsaPkcs1PrivateKey pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(
      byte[] pkcs1Key, CompositeMlDsaParameters compositeParameters)
      throws GeneralSecurityException {
    if (!compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA2048_PKCS1)
        && !compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA3072_PKCS1)
        && !compositeParameters.getClassicalAlgorithm().equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
      throw new GeneralSecurityException(
          "Not an RSA-PKCS1 classical algorithm: " + compositeParameters.getClassicalAlgorithm());
    }

    RsaSsaPkcs1Parameters rsaParameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(getRsaModulusSizeBits(compositeParameters))
            // This might not technically be true, but we'll verify in Asn1Util call below.
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(getRsaPkcs1SigHashType(compositeParameters))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return Asn1Util.pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(pkcs1Key, rsaParameters);
  }

  // Values from
  // https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-maximum-key-and-signature-s
  public static int getSignatureLength(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.MlDsaInstance mlDsaInstance = parameters.getMlDsaInstance();
    CompositeMlDsaParameters.ClassicalAlgorithm classicalAlgorithm =
        parameters.getClassicalAlgorithm();

    if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_44)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.ED25519)) {
        return 2484;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PSS)) {
        return 2676;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA2048_PKCS1)) {
        return 2676;
      } else {
        throw new GeneralSecurityException("No known signature length for " + classicalAlgorithm);
      }
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_65)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.ED25519)) {
        return 3373;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
        return 3693;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
        return 3821;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PKCS1)) {
        return 3693;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PKCS1)) {
        return 3821;
      } else {
        throw new GeneralSecurityException("No known signature length for " + classicalAlgorithm);
      }
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_87)) {
      if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA3072_PSS)) {
        return 5011;
      } else if (classicalAlgorithm.equals(ClassicalAlgorithm.RSA4096_PSS)) {
        return 5139;
      } else {
        throw new GeneralSecurityException("No known signature length for " + classicalAlgorithm);
      }
    } else {
      throw new GeneralSecurityException("Unsupported ML-DSA instance: " + mlDsaInstance);
    }
  }
}
