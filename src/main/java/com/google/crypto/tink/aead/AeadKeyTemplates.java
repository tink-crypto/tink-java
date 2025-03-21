// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.Aead} keys.
 *
 * <p>We recommend to avoid this class to keep dependencies small.
 *
 * <ul>
 *   <li>Using this class adds a dependency on protobuf. We hope that eventually it is possible to
 *       use Tink without a dependency on protobuf.
 *   <li>Using this class adds a dependency on classes for all involved key types.
 * </ul>
 *
 * These dependencies all come from static class member variables, which are initialized when the
 * class is loaded. This implies that static analysis and code minimization tools (such as proguard)
 * cannot remove the usages either.
 *
 * <p>Instead, we recommend to use {@code KeysetHandle.generateEntryFromParametersName} or {@code
 * KeysetHandle.generateEntryFromParameters}.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@link com.google.crypto.tink.KeysetHandle#generateNew}. To generate a new keyset that contains a
 * single {@link com.google.crypto.tink.proto.AesGcmKey}, one can do:
 *
 * <pre>{@code
 * AeadConfig.register();
 * KeysetHandle handle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
 * Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class AeadKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final KeyTemplate AES128_GCM = createAesGcmKeyTemplate(16);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final KeyTemplate AES256_GCM = createAesGcmKeyTemplate(32);

  /**
   * A {@link KeyTemplate} that generates new instances of {@code
   * com.google.crypto.tink.proto.AesEaxKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final KeyTemplate AES128_EAX = createAesEaxKeyTemplate(16, 16);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesEaxKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final KeyTemplate AES256_EAX = createAesEaxKeyTemplate(32, 16);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacAeadKey} with the following parameters:
   *
   * <ul>
   *   <li>AES key size: 16 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 16 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final KeyTemplate AES128_CTR_HMAC_SHA256 =
      createAesCtrHmacAeadKeyTemplate(16, 16, 32, 16, HashType.SHA256);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacAeadKey} with the following parameters:
   *
   * <ul>
   *   <li>AES key size: 32 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 32 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final KeyTemplate AES256_CTR_HMAC_SHA256 =
      createAesCtrHmacAeadKeyTemplate(32, 16, 32, 32, HashType.SHA256);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.ChaCha20Poly1305Key}.
   *
   * @since 1.1.0
   */
  public static final KeyTemplate CHACHA20_POLY1305 =
      KeyTemplate.newBuilder()
          .setTypeUrl(ChaCha20Poly1305KeyManager.getKeyType())
          .setOutputPrefixType(OutputPrefixType.TINK)
          .build();

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.XChaCha20Poly1305Key}.
   *
   * @since 1.3.0
   */
  public static final KeyTemplate XCHACHA20_POLY1305 =
      KeyTemplate.newBuilder()
          .setTypeUrl(XChaCha20Poly1305KeyManager.getKeyType())
          .setOutputPrefixType(OutputPrefixType.TINK)
          .build();

  /**
   * @return a {@link KeyTemplate} containing a {@link AesGcmKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createAesGcmKeyTemplate(int keySize) {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder()
        .setKeySize(keySize)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesGcmKeyManager.getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link AesEaxKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createAesEaxKeyTemplate(int keySize, int ivSize) {
    AesEaxKeyFormat format = AesEaxKeyFormat.newBuilder()
        .setKeySize(keySize)
        .setParams(AesEaxParams.newBuilder().setIvSize(ivSize).build())
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesEaxKeyManager.getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link AesCtrHmacAeadKeyFormat} with some specific
   *     parameters.
   */
  public static KeyTemplate createAesCtrHmacAeadKeyTemplate(
      int aesKeySize, int ivSize, int hmacKeySize, int tagSize, HashType hashType) {
    AesCtrKeyFormat aesCtrKeyFormat = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
        .setKeySize(aesKeySize)
        .build();
    HmacKeyFormat hmacKeyFormat = HmacKeyFormat.newBuilder()
        .setParams(
            HmacParams.newBuilder().setHash(hashType).setTagSize(tagSize).build())
        .setKeySize(hmacKeySize)
        .build();
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(aesCtrKeyFormat)
        .setHmacKeyFormat(hmacKeyFormat)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesCtrHmacAeadKeyManager.getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * Returns a new {@link KeyTemplate} that can generate a {@link
   * com.google.crypto.tink.proto.KmsEnvelopeAeadKey} whose key encrypting key (KEK) is pointing to
   * {@code kekUri} and DEK template is {@code dekTemplate}. Keys generated by this key template
   * uses RAW output prefix to make them compatible with the remote KMS' encrypt/decrypt operations.
   * Unlike other templates, when you generate new keys with this template, Tink does not generate
   * new key material, but only creates a reference to the remote KEK.
   */
  public static KeyTemplate createKmsEnvelopeAeadKeyTemplate(
      String kekUri, KeyTemplate dekTemplate) {
    KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.newBuilder()
        .setDekTemplate(dekTemplate)
        .setKekUri(kekUri)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(KmsEnvelopeAeadKeyManager.getKeyType())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  private AeadKeyTemplates() {}
}
