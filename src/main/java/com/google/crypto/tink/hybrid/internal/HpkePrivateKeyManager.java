// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkeProtoSerialization;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.internal.KeyCreator;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Key manager that generates new {@link HpkePrivateKey} keys and produces new instances of {@link
 * HpkeDecrypt} primitives.
 */
public final class HpkePrivateKeyManager {
  private static final PrimitiveConstructor<HpkePrivateKey, HybridDecrypt>
      HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              HpkeDecrypt::create, HpkePrivateKey.class, HybridDecrypt.class);

  private static final PrimitiveConstructor<HpkePublicKey, HybridEncrypt>
      HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              HpkeEncrypt::create, HpkePublicKey.class, HybridEncrypt.class);

  private static final PrivateKeyManager<HybridDecrypt> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(), HybridDecrypt.class, com.google.crypto.tink.proto.HpkePrivateKey.parser());

  private static final KeyManager<HybridEncrypt> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          HpkePublicKeyManager.getKeyType(),
          HybridEncrypt.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.HpkePublicKey.parser());

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final KeyCreator<HpkeParameters> KEY_CREATOR = HpkeKeyCreator::createKey;

  /**
   * Registers an {@link HpkePrivateKeyManager} and an {@link HpkePublicKeyManager} with the
   * registry, so that HpkePrivateKey and HpkePublicKey key types can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Registering HPKE Hybrid Encryption is not supported in FIPS mode");
    }
    HpkeProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, HpkeParameters.class);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManager(legacyPublicKeyManager, /* newKeyAllowed= */ false);
  }

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
            .build());
    result.put(
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
            .build());
    result.put(
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build());
    result.put(
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    result.put(
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM_RAW",
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build());
    return Collections.unmodifiableMap(result);
  }

  private HpkePrivateKeyManager() {}
}
