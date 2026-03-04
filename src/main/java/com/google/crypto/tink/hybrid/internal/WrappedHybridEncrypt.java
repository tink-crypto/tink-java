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
package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper.PrimitiveFactory;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<HybridEncrypt>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key.
 */
public final class WrappedHybridEncrypt {
  private static class HybridEncryptWithId {
    public HybridEncryptWithId(HybridEncrypt hybridEncrypt, int id) {
      this.hybridEncrypt = hybridEncrypt;
      this.id = id;
    }

    public final HybridEncrypt hybridEncrypt;
    public final int id;
  }

  private static class WrappedHybridEncryptImpl implements HybridEncrypt {
    private final HybridEncryptWithId primary;
    private final MonitoringClient.Logger encLogger;

    WrappedHybridEncryptImpl(HybridEncryptWithId primary, MonitoringClient.Logger encLogger) {
      this.primary = primary;
      this.encLogger = encLogger;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
        throws GeneralSecurityException {
      if (primary.hybridEncrypt == null) {
        encLogger.logFailure();
        throw new GeneralSecurityException("keyset without primary key");
      }
      try {
        byte[] output = primary.hybridEncrypt.encrypt(plaintext, contextInfo);
        encLogger.log(primary.id, plaintext.length);
        return output;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }
  }

  public static HybridEncrypt create(
      KeysetHandleInterface keysetHandle, PrimitiveFactory<HybridEncrypt> factory)
      throws GeneralSecurityException {
    MonitoringClient.Logger encLogger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      encLogger = client.createLogger(keysetHandle, annotations, "hybrid_encrypt", "encrypt");
    } else {
      encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    KeysetHandleInterface.Entry primary = keysetHandle.getPrimary();
    return new WrappedHybridEncryptImpl(
        new HybridEncryptWithId(factory.create(primary), primary.getId()), encLogger);
  }

  private WrappedHybridEncrypt() {}
}
