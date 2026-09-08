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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.MlDsaParameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves;
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

  public static boolean isEcdsaAlgorithm(String algorithm) {
    return algorithm.equals(MLDSA44_ECDSA_P256_SHA256)
        || algorithm.equals(MLDSA65_ECDSA_P256_SHA512)
        || algorithm.equals(MLDSA65_ECDSA_P384_SHA512)
        || algorithm.equals(MLDSA87_ECDSA_P384_SHA512)
        || algorithm.equals(MLDSA87_ECDSA_P521_SHA512);
  }

  public static MlDsaParameters.MlDsaInstance getMlDsaParametersMlDsaInstance(
      CompositeMlDsaParameters parameters) throws GeneralSecurityException {
    CompositeMlDsaParameters.MlDsaInstance mlDsaInstance = parameters.getMlDsaInstance();
    if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_44)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_44;
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_65)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_65;
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_87)) {
      return MlDsaParameters.MlDsaInstance.ML_DSA_87;
    } else {
      throw new GeneralSecurityException("Unsupported ML-DSA instance: " + mlDsaInstance);
    }
  }

  // As per
  // https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-maximum-key-and-signature-s
  public static int getMlDsaPublicKeySize(CompositeMlDsaParameters parameters)
      throws GeneralSecurityException {
    CompositeMlDsaParameters.MlDsaInstance mlDsaInstance = parameters.getMlDsaInstance();
    if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_44)) {
      return 1312;
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_65)) {
      return 1952;
    } else if (mlDsaInstance.equals(MlDsaInstance.ML_DSA_87)) {
      return 2592;
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
            // This might not technically be true, but we'll verify in RsaAsn1Util call below.
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setMgf1HashType(getRsaMgf1HashType(compositeParameters))
            .setSigHashType(getRsaPssSigHashType(compositeParameters))
            .setSaltLengthBytes(getRsaSaltLengthBytes(compositeParameters))
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    return RsaAsn1Util.pkcs1RsaKeyToRsaSsaPssPrivateKey(pkcs1Key, rsaParameters);
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
            // This might not technically be true, but we'll verify in RsaAsn1Util call below.
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(getRsaPkcs1SigHashType(compositeParameters))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return RsaAsn1Util.pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(pkcs1Key, rsaParameters);
  }

  /**
   * Returns the {@link EcdsaParameters} corresponding to the classical ECDSA component of the given
   * {@link CompositeMlDsaParameters}, as specified in
   * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html#name-algorithm-identifiers-and-p.
   */
  public static EcdsaParameters getEcdsaParameters(CompositeMlDsaParameters compositeParameters)
      throws GeneralSecurityException {
    ClassicalAlgorithm alg = compositeParameters.getClassicalAlgorithm();
    if (alg.equals(ClassicalAlgorithm.ECDSA_P256)) {
      return EcdsaParameters.builder()
          .setHashType(EcdsaParameters.HashType.SHA256)
          .setCurveType(EcdsaParameters.CurveType.NIST_P256)
          .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
          .setVariant(EcdsaParameters.Variant.NO_PREFIX)
          .build();
    } else if (alg.equals(ClassicalAlgorithm.ECDSA_P384)) {
      return EcdsaParameters.builder()
          .setHashType(EcdsaParameters.HashType.SHA384)
          .setCurveType(EcdsaParameters.CurveType.NIST_P384)
          .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
          .setVariant(EcdsaParameters.Variant.NO_PREFIX)
          .build();
    } else if (alg.equals(ClassicalAlgorithm.ECDSA_P521)) {
      return EcdsaParameters.builder()
          .setHashType(EcdsaParameters.HashType.SHA512)
          .setCurveType(EcdsaParameters.CurveType.NIST_P521)
          .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
          .setVariant(EcdsaParameters.Variant.NO_PREFIX)
          .build();
    } else {
      throw new GeneralSecurityException("Not an ECDSA classical algorithm: " + alg);
    }
  }

  public static EllipticCurves.CurveType getEllipticCurveType(
      CompositeMlDsaParameters compositeParameters) throws GeneralSecurityException {
    ClassicalAlgorithm alg = compositeParameters.getClassicalAlgorithm();
    if (alg.equals(ClassicalAlgorithm.ECDSA_P256)) {
      return EllipticCurves.CurveType.NIST_P256;
    } else if (alg.equals(ClassicalAlgorithm.ECDSA_P384)) {
      return EllipticCurves.CurveType.NIST_P384;
    } else if (alg.equals(ClassicalAlgorithm.ECDSA_P521)) {
      return EllipticCurves.CurveType.NIST_P521;
    } else {
      throw new GeneralSecurityException("Not an ECDSA classical algorithm: " + alg);
    }
  }

  @AccessesPartialKey
  public static EcdsaPrivateKey sec1EcKeyToEcdsaPrivateKey(
      byte[] sec1Key, CompositeMlDsaParameters compositeParameters)
      throws GeneralSecurityException {
    EcdsaParameters ecdsaParams = getEcdsaParameters(compositeParameters);
    return EcdsaAsn1Util.sec1EcKeyToEcdsaPrivateKey(
        sec1Key, ecdsaParams, InsecureSecretKeyAccess.get());
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
