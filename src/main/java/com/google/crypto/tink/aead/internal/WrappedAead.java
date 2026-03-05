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

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.aead.AeadKey;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/** An implementation of an {@link Aead} based on a {@link KeysetHandleInterface}. */
public final class WrappedAead {

  private static final class AeadWithId {
    public AeadWithId(Aead aead, int id) {
      this.aead = aead;
      this.id = id;
    }

    public final Aead aead;
    public final int id;
  }

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

  private static class WrappedAeadImpl implements Aead {
    private final AeadWithId primary;
    private final PrefixMap<AeadWithId> allAeads;
    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    private WrappedAeadImpl(
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

  public static Aead create(
      KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<Aead> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<WrappedAead.AeadWithId> builder = new PrefixMap.Builder<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        builder.put(
            getOutputPrefix(entry.getKey()),
            new WrappedAead.AeadWithId(factory.create(entry), entry.getId()));
      }
    }
    MonitoringClient.Logger encLogger;
    MonitoringClient.Logger decLogger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      encLogger = client.createLogger(keysetHandle, annotations, "aead", "encrypt");
      decLogger = client.createLogger(keysetHandle, annotations, "aead", "decrypt");
    } else {
      encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedAeadImpl(
        new WrappedAead.AeadWithId(
            factory.create(keysetHandle.getPrimary()), keysetHandle.getPrimary().getId()),
        builder.build(),
        encLogger,
        decLogger);
  }

  private WrappedAead() {}
}
