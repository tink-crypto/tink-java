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

package com.google.crypto.tink.daead.internal;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.daead.DeterministicAeadKey;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/** An implementation of an {@link DeterministicAead} based on a {@link KeysetHandleInterface}. */
public final class WrappedDeterministicAead {
  private static class DeterministicAeadWithId {
    public DeterministicAeadWithId(DeterministicAead daead, int id) {
      this.daead = daead;
      this.id = id;
    }

    public final DeterministicAead daead;
    public final int id;
  }

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof DeterministicAeadKey) {
      return ((DeterministicAeadKey) key).getOutputPrefix();
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

  private static class WrappedDeterministicAeadImpl implements DeterministicAead {
    private final DeterministicAeadWithId primary;
    private final PrefixMap<DeterministicAeadWithId> allDaeads;
    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    WrappedDeterministicAeadImpl(
        DeterministicAeadWithId primary,
        PrefixMap<DeterministicAeadWithId> allDaeads,
        MonitoringClient.Logger encLogger,
        MonitoringClient.Logger decLogger) {
      this.primary = primary;
      this.allDaeads = allDaeads;
      this.encLogger = encLogger;
      this.decLogger = decLogger;
    }

    @Override
    public byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        byte[] result = primary.daead.encryptDeterministically(plaintext, associatedData);
        encLogger.log(primary.id, plaintext.length);
        return result;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }

    @Override
    public byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      for (DeterministicAeadWithId aeadWithId : allDaeads.getAllWithMatchingPrefix(ciphertext)) {
        try {
          byte[] result = aeadWithId.daead.decryptDeterministically(ciphertext, associatedData);
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

  public static DeterministicAead create(
      KeysetHandleInterface handle, PrimitiveWrapper.PrimitiveFactory<DeterministicAead> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<DeterministicAeadWithId> builder = new PrefixMap.Builder<>();
    for (int i = 0; i < handle.size(); i++) {
      KeysetHandleInterface.Entry entry = handle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        DeterministicAead deterministicAead = factory.create(entry);
        builder.put(
            getOutputPrefix(entry.getKey()),
            new DeterministicAeadWithId(deterministicAead, entry.getId()));
      }
    }
    MonitoringClient.Logger encLogger;
    MonitoringClient.Logger decLogger;
    MonitoringAnnotations annotations = handle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      encLogger = client.createLogger(handle, annotations, "daead", "encrypt");
      decLogger = client.createLogger(handle, annotations, "daead", "decrypt");
    } else {
      encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedDeterministicAeadImpl(
        new DeterministicAeadWithId(
            factory.create(handle.getPrimary()), handle.getPrimary().getId()),
        builder.build(),
        encLogger,
        decLogger);
  }

  private WrappedDeterministicAead() {}
}
