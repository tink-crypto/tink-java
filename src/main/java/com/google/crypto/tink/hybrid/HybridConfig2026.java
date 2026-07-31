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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.hybrid.internal.EciesKeyCreator;
import com.google.crypto.tink.hybrid.internal.HpkeKeyCreator;
import com.google.crypto.tink.hybrid.subtle.EciesDecrypt;
import com.google.crypto.tink.hybrid.subtle.EciesEncrypt;
import com.google.crypto.tink.hybrid.subtle.EciesProtoSerialization;
import com.google.crypto.tink.hybrid.subtle.HpkeDecrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeEncrypt;
import com.google.crypto.tink.hybrid.subtle.HpkeProtoSerialization;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import java.security.GeneralSecurityException;

/**
 * HybridConfig2026 contains the following algorithms for HybridEncrypt/HybridDecrypt:
 *
 * <ul>
 *   <li>Ecies
 *   <li>Hpke
 * </ul>
 */
public final class HybridConfig2026 {
  private HybridConfig2026() {}

  private static final HybridDecryptWrapper HYBRID_DECRYPT_WRAPPER = new HybridDecryptWrapper();
  private static final HybridEncryptWrapper HYBRID_ENCRYPT_WRAPPER = new HybridEncryptWrapper();
  private static final Configuration CONFIGURATION = create();

  /** Returns an instance of the {@code HybridConfig2026}. */
  public static Configuration get() throws GeneralSecurityException {
    if (TinkFipsUtil.useOnlyFips()) {
      throw new GeneralSecurityException(
          "Cannot use non-FIPS-compliant HybridConfig2026 in FIPS mode");
    }
    return CONFIGURATION;
  }

  private static final String ECIES_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  private static final String ECIES_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  private static final String HPKE_PRIVATE_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  private static final String HPKE_PUBLIC_KEY_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.HpkePublicKey";

  @LowLevelCryptoCaller
  private static Configuration create() {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(HybridDecrypt.class, HybridDecrypt.class, HYBRID_DECRYPT_WRAPPER::wrap)
        .addPrimitiveWrapper(HybridEncrypt.class, HybridEncrypt.class, HYBRID_ENCRYPT_WRAPPER::wrap)
        // Ecies
        .addPrimitiveConstructor(EciesDecrypt::create, EciesPrivateKey.class, HybridDecrypt.class)
        .addPrimitiveConstructor(EciesEncrypt::create, EciesPublicKey.class, HybridEncrypt.class)
        .addKeySerializer(EciesPrivateKey.class, EciesProtoSerialization::serializePrivateKey)
        .addKeySerializer(EciesPublicKey.class, EciesProtoSerialization::serializePublicKey)
        .addParametersSerializer(
            EciesParameters.class, EciesProtoSerialization::serializeParameters)
        .addKeyParser(ECIES_PRIVATE_KEY_TYPE_URL, EciesProtoSerialization::parsePrivateKey)
        .addKeyParser(ECIES_PUBLIC_KEY_TYPE_URL, EciesProtoSerialization::parsePublicKey)
        .addKeyCreator(EciesParameters.class, EciesKeyCreator::createKey)
        .addParametersParser(ECIES_PRIVATE_KEY_TYPE_URL, EciesProtoSerialization::parseParameters)
        // Hpke
        .addPrimitiveConstructor(HpkeDecrypt::create, HpkePrivateKey.class, HybridDecrypt.class)
        .addPrimitiveConstructor(HpkeEncrypt::create, HpkePublicKey.class, HybridEncrypt.class)
        .addKeySerializer(HpkePrivateKey.class, HpkeProtoSerialization::serializePrivateKey)
        .addKeySerializer(HpkePublicKey.class, HpkeProtoSerialization::serializePublicKey)
        .addParametersSerializer(HpkeParameters.class, HpkeProtoSerialization::serializeParameters)
        .addKeyParser(HPKE_PRIVATE_KEY_TYPE_URL, HpkeProtoSerialization::parsePrivateKey)
        .addKeyParser(HPKE_PUBLIC_KEY_TYPE_URL, HpkeProtoSerialization::parsePublicKey)
        .addKeyCreator(HpkeParameters.class, HpkeKeyCreator::createKey)
        .addParametersParser(HPKE_PRIVATE_KEY_TYPE_URL, HpkeProtoSerialization::parseParameters)
        .build();
  }
}
