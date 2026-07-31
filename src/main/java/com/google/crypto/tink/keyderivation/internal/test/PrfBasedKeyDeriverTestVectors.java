// Copyright 2023 Google LLC
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

package com.google.crypto.tink.keyderivation.internal.test;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.PredefinedPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/** Test vectors for PRF-based key derivation. */
@AccessesPartialKey
public final class PrfBasedKeyDeriverTestVectors {

  /**
   * A test vector: if we use prfKey with derivedKeyParameters and salt Hex.decode(inputHex) we get
   * expectedKey.
   *
   * <p>Note that the test vector doesn't specify the derivation key itself. In particular, the
   * idRequirement of the derivationKey is obtained from the expected key (since it should always be
   * the same).
   */
  public static final class TestVector {
    public final PrfKey prfKey;
    public final Parameters derivedKeyParameters;
    public final String inputHex;
    public final Key expectedKey;

    public TestVector(
        PrfKey prfKey, Parameters derivedKeyParameters, String inputHex, Key expectedKey) {
      this.prfKey = prfKey;
      this.derivedKeyParameters = derivedKeyParameters;
      this.inputHex = inputHex;
      this.expectedKey = expectedKey;
    }
  }

  private static final PrfKey FIXED_PRF_KEY =
      exceptionIsBug(
          () ->
              HkdfPrfKey.builder()
                  .setParameters(
                      HkdfPrfParameters.builder()
                          .setKeySizeBytes(32)
                          .setHashType(HkdfPrfParameters.HashType.SHA256)
                          .build())
                  .setKeyBytes(
                      SecretBytes.copyFrom(
                          Hex.decode(
                              "0102030405060708091011121314151617181920212123242526272829303132"),
                          InsecureSecretKeyAccess.get()))
                  .build());

  private static SecretBytes secretBytesFromHex(String hex) {
    return SecretBytes.copyFrom(Hex.decode(hex), InsecureSecretKeyAccess.get());
  }

  // Note: most test vectors use the FIXED_PRF_KEY and "000102" as seed. In this case, the first
  // 64 bytes of the output of the PRF are:
  // 94e397d674deda6e965295698491a3fe b69838a35f1d48143f3c4cbad90eeb24
  // 9c8ddea6d09adc5f89a9a190122b095d 34e166df93b36f417d63baac78115ac3
  public static TestVector[] createTestVectors() throws GeneralSecurityException {
    return new TestVector[] {
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_GCM,
          "",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(secretBytesFromHex("1b73bdf5293cc533d635f263e35913ec"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_GCM,
          "000102",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES256_GCM,
          "000102",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES256_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_CTR_HMAC_SHA256,
          "000102",
          AesCtrHmacAeadKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256)
              .setIdRequirement(12345)
              .setAesKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
              .setHmacKeyBytes(
                  secretBytesFromHex(
                      "b69838a35f1d48143f3c4cbad90eeb249c8ddea6d09adc5f89a9a190122b095d"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK),
          "000102",
          XChaCha20Poly1305Key.create(
              XChaCha20Poly1305Parameters.Variant.TINK,
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"),
              1234)),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedDeterministicAeadParameters.AES256_SIV,
          "000102",
          AesSivKey.builder()
              .setParameters(PredefinedDeterministicAeadParameters.AES256_SIV)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"
                          + "9c8ddea6d09adc5f89a9a190122b095d34e166df93b36f417d63baac78115ac3"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedMacParameters.HMAC_SHA256_256BITTAG,
          "000102",
          HmacKey.builder()
              .setParameters(PredefinedMacParameters.HMAC_SHA256_256BITTAG)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedPrfParameters.HMAC_SHA256_PRF,
          "000102",
          HmacPrfKey.builder()
              .setParameters(PredefinedPrfParameters.HMAC_SHA256_PRF)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedSignatureParameters.ED25519,
          "000102",
          Ed25519PrivateKey.create(
              Ed25519PublicKey.create(
                  Ed25519Parameters.Variant.TINK,
                  Bytes.copyFrom(
                      Hex.decode(
                          "c9855bf7fcb4f975e61eac19a530d490f276ddcb1908fcf2ca13329981d58bab")),
                  1234),
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
      new TestVector(
          FIXED_PRF_KEY,
          Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX),
          "000102",
          Ed25519PrivateKey.create(
              Ed25519PublicKey.create(
                  Ed25519Parameters.Variant.NO_PREFIX,
                  Bytes.copyFrom(
                      Hex.decode(
                          "c9855bf7fcb4f975e61eac19a530d490f276ddcb1908fcf2ca13329981d58bab")),
                  /* idRequirement= */ null),
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
          "000102",
          AesGcmHkdfStreamingKey.create(
              PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
    };
  }

  public static TestVector createAesGcmSivTestVector() throws GeneralSecurityException {
    return new TestVector(
        FIXED_PRF_KEY,
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build(),
        "000102",
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
            .build());
  }

  private PrfBasedKeyDeriverTestVectors() {}
}
