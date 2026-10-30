// Copyright 2022 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.daead.DeterministicAeadConfig2026;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the Hybrid package. Uses only the public API. */
@RunWith(Theories.class)
public final class HybridTest {

  @BeforeClass
  public static void setUp() throws Exception {
    HybridConfig.register();
  }

  @DataPoints("parameters")
  public static final HybridParameters[] parameters =
      exceptionIsBug(
          () ->
              new HybridParameters[] {
                PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
                PredefinedHybridParameters
                    .ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX,
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                    .setVariant(EciesParameters.Variant.NO_PREFIX)
                    .setDemParameters(
                        AesCtrHmacAeadParameters.builder()
                            .setAesKeySizeBytes(16)
                            .setHmacKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .setIvSizeBytes(16)
                            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                            .build())
                    .build(),
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                    .setVariant(EciesParameters.Variant.TINK)
                    .setDemParameters(
                        AesCtrHmacAeadParameters.builder()
                            .setAesKeySizeBytes(16)
                            .setHmacKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .setIvSizeBytes(16)
                            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                            .build())
                    .build(),
                HpkeParameters.builder()
                    .setVariant(HpkeParameters.Variant.NO_PREFIX)
                    .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                    .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                    .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                    .build(),
                HpkeParameters.builder()
                    .setVariant(HpkeParameters.Variant.TINK)
                    .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                    .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                    .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
                    .build(),
                HpkeParameters.builder()
                    .setVariant(HpkeParameters.Variant.TINK)
                    .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                    .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                    .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                    .build(),
                HpkeParameters.builder()
                    .setVariant(HpkeParameters.Variant.NO_PREFIX)
                    .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
                    .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
                    .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                    .build(),
                HpkeParameters.builder()
                    .setVariant(HpkeParameters.Variant.TINK)
                    .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
                    .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
                    .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                    .build()
              });

  @Theory
  public void createEncryptDecrypt(@FromDataPoints("parameters") HybridParameters parameters)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle privateHandle = KeysetHandle.generateNew(parameters, HybridConfig2026.get());
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    HybridEncrypt encrypter =
        publicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);
    HybridDecrypt decrypter =
        privateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

    KeysetHandle otherPrivateHandle = KeysetHandle.generateNew(parameters, HybridConfig2026.get());
    HybridDecrypt otherDecrypter =
        otherPrivateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);
    assertThrows(
        GeneralSecurityException.class, () -> otherDecrypter.decrypt(ciphertext, contextInfo));

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(invalid, contextInfo));
    assertThrows(GeneralSecurityException.class, () -> decrypter.decrypt(empty, contextInfo));
    assertThat(decrypter.decrypt(encrypter.encrypt(empty, contextInfo), contextInfo))
        .isEqualTo(empty);
    assertThat(decrypter.decrypt(encrypter.encrypt(plaintext, empty), empty)).isEqualTo(plaintext);
  }

  // Keyset with one private key for HybridDecrypt, serialized in Tink's JSON format.
  private static final String JSON_PRIVATE_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 1885000158,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePrivateKey\","
      + "        \"value\": \"GiBXM1jmpJqe7HUTTkQxRwEld3bvIPTBhqGcI09ki9H0mRIqGiCwWh0y63G"
      + "fObeWuYZcuLIiFz+15ElOFL7rhf9rbWxdBBIGGAEQAQgB\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 1885000158,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  // Keyset with the corresponding public key for HybridEncrypt, serialized in Tink's JSON format.
  private static final String JSON_PUBLIC_KEYSET = ""
      + "{"
      + "  \"primaryKeyId\": 1885000158,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePublicKey\","
      + "        \"value\": \"GiCwWh0y63GfObeWuYZcuLIiFz+15ElOFL7rhf9rbWxdBBIGGAEQAQgB\","
      + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 1885000158,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  @Theory
  public void readKeysetEncryptDecrypt_success()
      throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PRIVATE_KEYSET, HybridConfig2026.get(), InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PUBLIC_KEYSET, HybridConfig2026.get(), InsecureSecretKeyAccess.get());

    HybridEncrypt encrypter =
        publicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);
    HybridDecrypt decrypter =
        privateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }

  // Keyset with multiple keys. The first key is the same as in JSON_PRIVATE_KEYSET. The second
  // key is the primary key and will be used for signing.
  private static final String JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 405658073,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePrivateKey\","
          + "        \"value\": \"GiBXM1jmpJqe7HUTTkQxRwEld3bvIPTBhqGcI09ki9H0mRIqGiCwWh0y63G"
          + "fObeWuYZcuLIiFz+15ElOFL7rhf9rbWxdBBIGGAEQAQgB\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1885000158,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey\","
          + "        \"value\": \"GiAGLU3EgraobyU/aOJalcfR2jUUwK/ubd5mTYHIzLHBnBKiASIgJDF8fcN"
          + "yDS6BcgYpeVPkJ2/ZBG+Mum30OId4D4CzDuQaIP9J2qo487Shr+MxMIkE3VvMro1r4Z+VFoTP3QWVTpz"
          + "iElwYARJSElAYARISEggQIAoEEBAIAwoGEBAKAggQCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5"
          + "jcnlwdG8udGluay5BZXNDdHJIbWFjQWVhZEtleQoEEAMIAg==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 405658073,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePrivateKey\","
          + "        \"value\": \"GiAnd0VLE8exo149gJ49nkifg03YQLNnRMKfna0AdfYjnBIqGiABOUjRp8F"
          + "QgppUbZlHCkxRgxGc3jYiChCkm+pf9BL3YhIGGAIQAQgB\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 2085058073,"
          + "      \"outputPrefixType\": \"LEGACY\""
          + "    }"
          + "  ]"
          + "}";

  // Keyset with the public keys of the keys from JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS.
  private static final String JSON_PUBLIC_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 405658073,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePublicKey\","
          + "        \"value\": \"GiCwWh0y63GfObeWuYZcuLIiFz+15ElOFL7rhf9rbWxdBBIGGAEQAQgB\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1885000158,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey\","
          + "        \"value\": \"IiAkMXx9w3INLoFyBil5U+Qnb9kEb4y6bfQ4h3gPgLMO5Bog/0naqjjztKG"
          + "v4zEwiQTdW8yujWvhn5UWhM/dBZVOnOISXBgBElISUBgBEhISCBAgCgQQEAgDCgYQEAoCCBAKOHR5cGU"
          + "uZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkFlc0N0ckhtYWNBZWFkS2V5CgQQAwgC\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 405658073,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.HpkePublicKey\","
          + "        \"value\": \"GiABOUjRp8FQgppUbZlHCkxRgxGc3jYiChCkm+pf9BL3YhIGGAIQAQgB\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 2085058073,"
          + "      \"outputPrefixType\": \"LEGACY\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeysetWithEncryptDecrypt()
      throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PRIVATE_KEYSET_WITH_MULTIPLE_KEYS,
            HybridConfig2026.get(),
            InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PUBLIC_KEYSET_WITH_MULTIPLE_KEYS,
            HybridConfig2026.get(),
            InsecureSecretKeyAccess.get());

    HybridEncrypt encrypter =
        publicHandle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);
    HybridDecrypt decrypter =
        privateHandle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);

    // Also test that decrypter can decrypt ciphertext of a non-primary key. We use
    // JSON_PUBLIC_KEYSET to create a ciphertext with the first key.
    KeysetHandle publicHandle1 =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_PUBLIC_KEYSET, HybridConfig2026.get(), InsecureSecretKeyAccess.get());
    HybridEncrypt encrypter1 =
        publicHandle1.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class);
    byte[] ciphertext1 = encrypter1.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext1, contextInfo)).isEqualTo(plaintext);
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the HybridEncrypt
  // or HybridDecrypt.
  private static final String JSON_DAEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 961932622,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"EkCJ9r5iwc5uxq5ugFyrHXh5dijTa7qalWUgZ8Gf08RxNd545FjtLMYL7ObcaFtCS"
          + "kvV2+7u6F2DN+kqUjAfkf2W\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 961932622,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void getPrimitiveFromNonSignatureKeyset_throws()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_DAEAD_KEYSET, DeterministicAeadConfig2026.get(), InsecureSecretKeyAccess.get());
    // Test that the keyset can create a DeterministicAead primitive, but neither HybridEncrypt
    // nor HybridDecrypt primitives.
    Object unused = handle.getPrimitive(DeterministicAeadConfig2026.get(), DeterministicAead.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(HybridConfig2026.get(), HybridEncrypt.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(HybridConfig2026.get(), HybridDecrypt.class));
  }
}
