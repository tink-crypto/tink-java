// Copyright 2017 Google LLC
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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.aead.internal.LegacyFullAead;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/**
 * AeadWrapper is the implementation of SetWrapper for the Aead primitive.
 *
 * <p>Key rotation works as follows: each ciphertext is prefixed with the keyId. When decrypting, we
 * first try all primitives whose keyId starts with the prefix of the ciphertext. If none of these
 * succeed, we try the raw primitives. If any succeeds, we return the ciphertext, otherwise we
 * simply throw a GeneralSecurityException.
 */
public class AeadWrapper implements PrimitiveWrapper<Aead, Aead> {
  private static class AeadWithId {
    public AeadWithId(Aead aead, int id) {
      this.aead = aead;
      this.id = id;
    }

    public final Aead aead;
    public final int id;
  }

  private static final AeadWrapper WRAPPER = new AeadWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Aead>
      LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullAead::create, LegacyProtoKey.class, Aead.class);

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof AeadKey) {
      return ((AeadKey) key).getOutputPrefix();
    }
    if (key instanceof LegacyProtoKey) {
      return ((LegacyProtoKey) key).getOutputPrefix();
    }
    throw new GeneralSecurityException(
        "Cannot get output prefix for key of class "
            + key.getClass().getName()
            + " with parameters "
            + key.getParameters());
  }

  private static class WrappedAead implements Aead {
    private final AeadWithId primary;
    private final PrefixMap<AeadWithId> allAeads;
    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    private WrappedAead(
        AeadWithId primary,
        PrefixMap<AeadWithId> allAeads,
        MonitoringClient.Logger encLogger,
        MonitoringClient.Logger decLogger) {
      this.primary = primary;
      this.allAeads = allAeads;
      this.encLogger = encLogger;
      this.decLogger = decLogger;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        byte[] result = primary.aead.encrypt(plaintext, associatedData);
        encLogger.log(primary.id, plaintext.length);
        return result;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      for (AeadWithId aeadWithId : allAeads.getAllWithMatchingPrefix(ciphertext)) {
        try {
          byte[] result = aeadWithId.aead.decrypt(ciphertext, associatedData);
          decLogger.log(aeadWithId.id, ciphertext.length);
          return result;
        } catch (GeneralSecurityException ignored) {
          // ignore and continue trying
        }
      }
      decLogger.logFailure();
      // nothing works.
      throw new GeneralSecurityException("decryption failed");
    }
  }

  AeadWrapper() {}

  @Override
  public Aead wrap(
      KeysetHandleInterface keysetHandle,
      MonitoringAnnotations annotations,
      PrimitiveFactory<Aead> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<AeadWithId> builder = new PrefixMap.Builder<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        builder.put(
            getOutputPrefix(entry.getKey()), new AeadWithId(factory.create(entry), entry.getId()));
      }
    }
    MonitoringClient.Logger encLogger;
    MonitoringClient.Logger decLogger;
    if (!annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      encLogger = client.createLogger(keysetHandle, annotations, "aead", "encrypt");
      decLogger = client.createLogger(keysetHandle, annotations, "aead", "decrypt");
    } else {
      encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedAead(
        new AeadWithId(
            factory.create(keysetHandle.getPrimary()), keysetHandle.getPrimary().getId()),
        builder.build(),
        encLogger,
        decLogger);
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }

  @Override
  public Class<Aead> getInputPrimitiveClass() {
    return Aead.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_AEAD_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code AeadWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
