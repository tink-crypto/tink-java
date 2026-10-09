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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.LowLevelCryptoCaller;
import com.google.crypto.tink.aead.internal.LegacyFullAead;
import com.google.crypto.tink.aead.internal.WrappedAead;
import com.google.crypto.tink.internal.ProtoBasedConfigurationBuilder;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

/**
 * KmsAeadConfig2026 contains the following primitives and algorithms for {@link Aead}:
 *
 * <ul>
 *   <li>{@link LegacyKmsAeadKey}
 *   <li>{@link LegacyKmsEnvelopeAeadKey}
 * </ul>
 */
public final class KmsAeadConfig2026 {
  private KmsAeadConfig2026() {}

  private static final String KMS_AEAD_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";
  private static final String KMS_ENVELOPE_AEAD_TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  private static final Configuration GLOBAL_KMS_CLIENTS_CONFIGURATION = create(KmsClients::get);

  /**
   * Returns a {@link Configuration} instance that resolves KMS key URIs using the global {@link
   * KmsClients} registry.
   */
  public static Configuration getUsingGlobalKmsClients() {
    return GLOBAL_KMS_CLIENTS_CONFIGURATION;
  }

  /**
   * Returns a {@link Configuration} instance that resolves KMS key URIs using the provided {@code
   * kmsClients}.
   */
  public static Configuration getForKmsClients(KmsClient... kmsClients) {
    List<KmsClient> clients = Arrays.asList(Arrays.copyOf(kmsClients, kmsClients.length));
    return create(keyUri -> getKmsClient(clients, keyUri));
  }

  private interface KmsClientResolver {
    KmsClient get(String keyUri) throws GeneralSecurityException;
  }

  private static KmsClient getKmsClient(List<KmsClient> kmsClients, String keyUri)
      throws GeneralSecurityException {
    for (KmsClient client : kmsClients) {
      if (client.doesSupport(keyUri)) {
        return client;
      }
    }
    throw new GeneralSecurityException("No KMS client does support: " + keyUri);
  }

  @AccessesPartialKey
  @LowLevelCryptoCaller
  private static Configuration create(KmsClientResolver kmsClientResolver) {
    return new ProtoBasedConfigurationBuilder()
        .addPrimitiveWrapper(Aead.class, Aead.class, WrappedAead::create)
        // KmsAead
        .addKeyCreator(LegacyKmsAeadParameters.class, LegacyKmsAeadKey::create)
        .addPrimitiveConstructor(
            key -> createKmsAead(key, kmsClientResolver), LegacyKmsAeadKey.class, Aead.class)
        .addKeySerializer(LegacyKmsAeadKey.class, LegacyKmsAeadProtoSerialization::serializeKey)
        .addParametersSerializer(
            LegacyKmsAeadParameters.class, LegacyKmsAeadProtoSerialization::serializeParameters)
        .addKeyParser(KMS_AEAD_TYPE_URL, LegacyKmsAeadProtoSerialization::parseKey)
        .addParametersParser(KMS_AEAD_TYPE_URL, LegacyKmsAeadProtoSerialization::parseParameters)
        // KmsEnvelopeAead
        .addKeyCreator(LegacyKmsEnvelopeAeadParameters.class, LegacyKmsEnvelopeAeadKey::create)
        .addPrimitiveConstructor(
            key -> createKmsEnvelopeAead(key, kmsClientResolver),
            LegacyKmsEnvelopeAeadKey.class,
            Aead.class)
        .addKeySerializer(
            LegacyKmsEnvelopeAeadKey.class, LegacyKmsEnvelopeAeadProtoSerialization::serializeKey)
        .addParametersSerializer(
            LegacyKmsEnvelopeAeadParameters.class,
            LegacyKmsEnvelopeAeadProtoSerialization::serializeParameters)
        .addKeyParser(
            KMS_ENVELOPE_AEAD_TYPE_URL, LegacyKmsEnvelopeAeadProtoSerialization::parseKey)
        .addParametersParser(
            KMS_ENVELOPE_AEAD_TYPE_URL, LegacyKmsEnvelopeAeadProtoSerialization::parseParameters)
        .build();
  }

  @AccessesPartialKey
  private static Aead createKmsAead(LegacyKmsAeadKey key, KmsClientResolver kmsClientResolver)
      throws GeneralSecurityException {
    String keyUri = key.getParameters().keyUri();
    Aead rawAead = kmsClientResolver.get(keyUri).getAead(keyUri);
    return LegacyFullAead.create(rawAead, key.getOutputPrefix());
  }

  @AccessesPartialKey
  private static Aead createKmsEnvelopeAead(
      LegacyKmsEnvelopeAeadKey key, KmsClientResolver kmsClientResolver)
      throws GeneralSecurityException {
    String kekUri = key.getParameters().getKekUri();
    Aead rawAead =
        KmsEnvelopeAead.create(
            key.getParameters().getDekParametersForNewKeys(),
            kmsClientResolver.get(kekUri).getAead(kekUri));
    return LegacyFullAead.create(rawAead, key.getOutputPrefix());
  }
}
