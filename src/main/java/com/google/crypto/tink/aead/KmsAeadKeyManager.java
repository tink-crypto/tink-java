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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.aead.internal.LegacyFullAead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KmsAeadKey;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * This key manager produces new instances of {@code Aead} that forwards encrypt/decrypt requests to
 * a key residing in a remote KMS.
 */
public final class KmsAeadKeyManager {
  private static Aead create(LegacyKmsAeadKey key) throws GeneralSecurityException {

    Aead rawAead =
        KmsClients.get(key.getParameters().keyUri()).getAead(key.getParameters().keyUri());
    return LegacyFullAead.create(rawAead, key.getOutputPrefix());
  }

  private static final PrimitiveConstructor<LegacyKmsAeadKey, Aead>
      LEGACY_KMS_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              KmsAeadKeyManager::create, LegacyKmsAeadKey.class, Aead.class);

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(), Aead.class, KeyMaterialType.REMOTE, KmsAeadKey.parser());

  /**
   * Creates a "new" key from a parameters object.
   *
   * <p>While this creates a new Key object, it doesn't actually create a new key. It simply creates
   * the key object corresponding to this parameters object. Creating a new key would require to
   * call an API in the KMS, which this method does not do.
   *
   * <p>The reason this method exists is that in the past, Tink did not provide an API for the user
   * to create a key object by themselves. Instead, users had to always create a Key from a key
   * template (which is now a Parameters object) via {@code KeysetHandle.generateNew(template);}. To
   * support old usages, we need to register this creator.
   */
  @AccessesPartialKey
  private static LegacyKmsAeadKey newKey(
      LegacyKmsAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return LegacyKmsAeadKey.create(parameters, idRequirement);
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<LegacyKmsAeadParameters> KEY_CREATOR =
      KmsAeadKeyManager::newKey;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.KmsAeadKey";
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering KMS AEAD is not supported in FIPS mode");
    }
    LegacyKmsAeadProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_KMS_AEAD_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, LegacyKmsAeadParameters.class);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * Returns a new {@link KeyTemplate} that can generate a {@link
   * com.google.crypto.tink.proto.KmsAeadKey} whose key is pointing to {@code keyUri}. Keys
   * generated by this key template use the RAW output prefix to make them compatible with the
   * remote KMS' encrypt/decrypt operations.
   *
   * <p>It requires that a {@code KmsClient} that can handle {@code keyUri} is registered. Avoid
   * registering it more than once.
   *
   * <p><b>Note: </b> Unlike other templates, when you call {@link KeysetHandle#generateNew} with
   * this template, Tink does not generate new key material, but only creates a reference to the
   * remote key.
   *
   * <p>It is often not necessary to use this function. Instead of registering a {@code KmsClient},
   * and creating an {@code Aead} using {@code
   * KeysetHandle.generateNew(KmsAeadKeyManager.createKeyTemplate(keyUri)).getPrimitive(RegistryConfiguration.get(),
   * Aead.class)}, you can create the {@code Aead} directly using {@code kmsClient.getAead(kekUri)},
   * without registering any {@code KmsClient}.
   */
  public static KeyTemplate createKeyTemplate(String keyUri) {
    try {
      return KeyTemplate.createFrom(LegacyKmsAeadParameters.create(keyUri));
    } catch (GeneralSecurityException e) {
      // This should never happen: LegacyKmsAeadParameters shouldn't throw.
      throw new IllegalArgumentException(e);
    }
  }

  private KmsAeadKeyManager() {}
}
