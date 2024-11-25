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

package com.google.crypto.tink.aead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;


/**
 * Pre-generated {@link com.google.crypto.tink.Parameters} objects for creating new instances of
 * {@link AeadKey}.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedAeadParameters {
  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesGcmKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final AesGcmParameters AES128_GCM =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesGcmKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final AesGcmParameters AES256_GCM =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesEaxKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final AesEaxParameters AES128_EAX =
      exceptionIsBug(
          () ->
              AesEaxParameters.builder()
                  .setIvSizeBytes(16)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesEaxKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final AesEaxParameters AES256_EAX =
      exceptionIsBug(
          () ->
              AesEaxParameters.builder()
                  .setIvSizeBytes(16)
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesCtrHmacAeadKey} with the following parameters:
   *
   * <ul>
   *   <li>AES key size: 16 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 16 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final AesCtrHmacAeadParameters AES128_CTR_HMAC_SHA256 =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(16)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setIvSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * AesCtrHmacAeadKey} with the following parameters:
   *
   * <ul>
   *   <li>AES key size: 32 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 32 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final AesCtrHmacAeadParameters AES256_CTR_HMAC_SHA256 =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(32)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(32)
                  .setIvSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                  .build());

  /**
   * A {@link com.google.crypto.tink.Parameters} object that generates new instances of {@link
   * ChaCha20Poly1305Key}.
   */
  public static final ChaCha20Poly1305Parameters CHACHA20_POLY1305 =
      ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);

  /**
   * A {@link com.google.crypto.tink.Parameters} object that generates new instances of {@link
   * XChaCha20Poly1305Key}.
   */
  public static final XChaCha20Poly1305Parameters XCHACHA20_POLY1305 =
      XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * XAesGcmKey}. This follows the algorithm defined in the <a
   * href="https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md">XAES-256-GCM specification</a>
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Nonce size: 24 bytes (12 bytes of salt, 12 bytes of AES-GCM IV)
   *   <li>Salt size: 12 bytes
   *   <li>Tag size: 16 bytes
   *   <li>Output prefix: TINK
   * </ul>
   */
  public static final XAesGcmParameters XAES_256_GCM_192_BIT_NONCE =
      exceptionIsBug(
          () -> XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, /* saltSizeBytes= */ 12));

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * XAesGcmKey}. This follows the algorithm defined in the <a
   * href="https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md">XAES-256-GCM specification</a>
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Nonce size: 24 bytes (12 bytes of salt, 12 bytes of AES-GCM IV)
   *   <li>Salt size: 12 bytes
   *   <li>Tag size: 16 bytes
   *   <li>Output prefix: NO_PREFIX
   * </ul>
   */
  public static final XAesGcmParameters XAES_256_GCM_192_BIT_NONCE_NO_PREFIX =
      exceptionIsBug(
          () ->
              XAesGcmParameters.create(
                  XAesGcmParameters.Variant.NO_PREFIX, /* saltSizeBytes= */ 12));

  /**
   * A {@link com.google.crypto.tink.Parameters} object for generating new instances of {@link
   * XAesGcmKey}. This follows the algorithm defined in the <a
   * href="https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md">XAES-256-GCM specification</a>,
   * except that the nonce size is 160 bits instead of 192 bits. The remaining 4 bytes are padded
   * with zeros.
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Nonce size: 20 bytes (8 bytes of salt, 12 bytes of AES-GCM IV)
   *   <li>Salt size: 8 bytes
   *   <li>Tag size: 16 bytes
   *   <li>Output prefix: NO_PREFIX
   * </ul>
   */
  public static final XAesGcmParameters XAES_256_GCM_160_BIT_NONCE_NO_PREFIX =
      exceptionIsBug(
          () ->
              XAesGcmParameters.create(
                  XAesGcmParameters.Variant.NO_PREFIX, /* saltSizeBytes= */ 8));

  public static final XAesGcmParameters X_AES_GCM_8_BYTE_SALT_NO_PREFIX =
      XAES_256_GCM_160_BIT_NONCE_NO_PREFIX;

  private PredefinedAeadParameters() {}
}
