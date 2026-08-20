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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.Asn1Util;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.ClassicalAlgorithm;
import com.google.crypto.tink.signature.CompositeMlDsaParameters.MlDsaInstance;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPrivateKey;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CompositeMlDsaUtil}. */
@RunWith(JUnit4.class)
@AccessesPartialKey
public final class CompositeMlDsaUtilTest {

  @BeforeClass
  public static void setUp() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  @Test
  public void getAlgorithmName_mlDsa44() throws Exception {
    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
                    .build()))
        .isEqualTo("MLDSA44-Ed25519-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
                    .build()))
        .isEqualTo("MLDSA44-ECDSA-P256-SHA256");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
                    .build()))
        .isEqualTo("MLDSA44-RSA2048-PSS-SHA256");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
                    .build()))
        .isEqualTo("MLDSA44-RSA2048-PKCS15-SHA256");
  }

  @Test
  public void getAlgorithmName_mlDsa65() throws Exception {
    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
                    .build()))
        .isEqualTo("MLDSA65-Ed25519-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
                    .build()))
        .isEqualTo("MLDSA65-ECDSA-P256-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
                    .build()))
        .isEqualTo("MLDSA65-ECDSA-P384-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
                    .build()))
        .isEqualTo("MLDSA65-RSA3072-PSS-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
                    .build()))
        .isEqualTo("MLDSA65-RSA4096-PSS-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
                    .build()))
        .isEqualTo("MLDSA65-RSA3072-PKCS15-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
                    .build()))
        .isEqualTo("MLDSA65-RSA4096-PKCS15-SHA512");
  }

  @Test
  public void getAlgorithmName_mlDsa87() throws Exception {
    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
                    .build()))
        .isEqualTo("MLDSA87-ECDSA-P384-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                    .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
                    .build()))
        .isEqualTo("MLDSA87-ECDSA-P521-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
                    .build()))
        .isEqualTo("MLDSA87-RSA3072-PSS-SHA512");

    assertThat(
            CompositeMlDsaUtil.getAlgorithmName(
                CompositeMlDsaParameters.builder()
                    .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
                    .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
                    .build()))
        .isEqualTo("MLDSA87-RSA4096-PSS-SHA512");
  }

  @Test
  public void getRsaSaltLengthBytes_returnsExpected() throws Exception {
    CompositeMlDsaParameters rsa2048PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaSaltLengthBytes(rsa2048PssParams)).isEqualTo(32);

    CompositeMlDsaParameters rsa3072PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaSaltLengthBytes(rsa3072PssParams)).isEqualTo(32);

    CompositeMlDsaParameters rsa4096PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaSaltLengthBytes(rsa4096PssParams)).isEqualTo(48);
  }

  @Test
  public void getRsaMgf1HashType_returnsExpected() throws Exception {
    CompositeMlDsaParameters rsa2048PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaMgf1HashType(rsa2048PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);

    CompositeMlDsaParameters rsa3072PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaMgf1HashType(rsa3072PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);

    CompositeMlDsaParameters rsa4096PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaMgf1HashType(rsa4096PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA384);
  }

  @Test
  public void getRsaPssSigHashType_returnsExpected() throws Exception {
    CompositeMlDsaParameters rsa2048PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPssSigHashType(rsa2048PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);

    CompositeMlDsaParameters rsa3072PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPssSigHashType(rsa3072PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA256);

    CompositeMlDsaParameters rsa4096PssParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPssSigHashType(rsa4096PssParams))
        .isEqualTo(RsaSsaPssParameters.HashType.SHA384);
  }

  @Test
  public void getRsaPkcs1SigHashType_returnsExpected() throws Exception {
    CompositeMlDsaParameters rsa2048Pkcs1Params =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPkcs1SigHashType(rsa2048Pkcs1Params))
        .isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA256);

    CompositeMlDsaParameters rsa3072Pkcs1Params =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPkcs1SigHashType(rsa3072Pkcs1Params))
        .isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA256);

    CompositeMlDsaParameters rsa4096Pkcs1Params =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaPkcs1SigHashType(rsa4096Pkcs1Params))
        .isEqualTo(RsaSsaPkcs1Parameters.HashType.SHA384);
  }

  @Test
  public void getRsaModulusSizeBits_works() throws Exception {
    CompositeMlDsaParameters rsa2048Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa2048Pss)).isEqualTo(2048);

    CompositeMlDsaParameters rsa2048Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa2048Pkcs1)).isEqualTo(2048);

    CompositeMlDsaParameters rsa3072Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa3072Pss)).isEqualTo(3072);

    CompositeMlDsaParameters rsa3072Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa3072Pkcs1)).isEqualTo(3072);

    CompositeMlDsaParameters rsa4096Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa4096Pss)).isEqualTo(4096);

    CompositeMlDsaParameters rsa4096Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getRsaModulusSizeBits(rsa4096Pkcs1)).isEqualTo(4096);
  }

  @Test
  public void getSignatureLength_returnsExpectedLengths() throws Exception {
    // ML-DSA-44 cases
    CompositeMlDsaParameters mlDsa44Ed25519 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa44Ed25519)).isEqualTo(2484);

    CompositeMlDsaParameters mlDsa44Ecdsa =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> CompositeMlDsaUtil.getSignatureLength(mlDsa44Ecdsa));

    CompositeMlDsaParameters mlDsa44Rsa2048Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa44Rsa2048Pss)).isEqualTo(2676);

    CompositeMlDsaParameters mlDsa44Rsa2048Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa44Rsa2048Pkcs1)).isEqualTo(2676);

    // ML-DSA-65 cases
    CompositeMlDsaParameters mlDsa65Ed25519 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ED25519)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa65Ed25519)).isEqualTo(3373);

    CompositeMlDsaParameters mlDsa65EcdsaP256 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P256)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaUtil.getSignatureLength(mlDsa65EcdsaP256));

    CompositeMlDsaParameters mlDsa65EcdsaP384 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaUtil.getSignatureLength(mlDsa65EcdsaP384));

    CompositeMlDsaParameters mlDsa65Rsa3072Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa65Rsa3072Pss)).isEqualTo(3693);

    CompositeMlDsaParameters mlDsa65Rsa4096Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa65Rsa4096Pss)).isEqualTo(3821);

    CompositeMlDsaParameters mlDsa65Rsa3072Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa65Rsa3072Pkcs1)).isEqualTo(3693);

    CompositeMlDsaParameters mlDsa65Rsa4096Pkcs1 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_65)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PKCS1)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa65Rsa4096Pkcs1)).isEqualTo(3821);

    // ML-DSA-87 cases
    CompositeMlDsaParameters mlDsa87EcdsaP384 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P384)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaUtil.getSignatureLength(mlDsa87EcdsaP384));

    CompositeMlDsaParameters mlDsa87EcdsaP521 =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.ECDSA_P521)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> CompositeMlDsaUtil.getSignatureLength(mlDsa87EcdsaP521));

    CompositeMlDsaParameters mlDsa87Rsa3072Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA3072_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa87Rsa3072Pss)).isEqualTo(5011);

    CompositeMlDsaParameters mlDsa87Rsa4096Pss =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_87)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA4096_PSS)
            .build();
    assertThat(CompositeMlDsaUtil.getSignatureLength(mlDsa87Rsa4096Pss)).isEqualTo(5139);
  }

  @Test
  public void pkcs1RsaKeyToRsaSsaPssPrivateKey_works() throws Exception {
    RsaSsaPssParameters pssParams =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    RsaSsaPssPrivateKey tinkPrivateKey =
        RsaSsaPssTestUtil.privateKeyFor2048BitParameters(pssParams, null);
    byte[] pkcs1Bytes = Asn1Util.rsaSsaPssPrivateKeyToPkcs1Bytes(tinkPrivateKey);

    CompositeMlDsaParameters compositeParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PSS)
            .build();

    RsaSsaPssPrivateKey parsedKey =
        CompositeMlDsaUtil.pkcs1RsaKeyToRsaSsaPssPrivateKey(pkcs1Bytes, compositeParams);

    assertThat(parsedKey.getPublicKey().getModulus())
        .isEqualTo(tinkPrivateKey.getPublicKey().getModulus());
    assertThat(parsedKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(
            tinkPrivateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()));
  }

  @Test
  public void pkcs1RsaKeyToRsaSsaPkcs1PrivateKey_works() throws Exception {
    RsaSsaPkcs1Parameters pkcs1Params =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    RsaSsaPkcs1PrivateKey tinkPrivateKey =
        RsaSsaPkcs1TestUtil.privateKeyFor2048BitParameters(pkcs1Params, null);
    byte[] pkcs1Bytes = Asn1Util.rsaSsaPkcs1PrivateKeyToPkcs1Bytes(tinkPrivateKey);

    CompositeMlDsaParameters compositeParams =
        CompositeMlDsaParameters.builder()
            .setMlDsaInstance(MlDsaInstance.ML_DSA_44)
            .setClassicalAlgorithm(ClassicalAlgorithm.RSA2048_PKCS1)
            .build();

    RsaSsaPkcs1PrivateKey parsedKey =
        CompositeMlDsaUtil.pkcs1RsaKeyToRsaSsaPkcs1PrivateKey(pkcs1Bytes, compositeParams);

    assertThat(parsedKey.getPublicKey().getModulus())
        .isEqualTo(tinkPrivateKey.getPublicKey().getModulus());
    assertThat(parsedKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(
            tinkPrivateKey.getPrivateExponent().getBigInteger(InsecureSecretKeyAccess.get()));
  }
}
