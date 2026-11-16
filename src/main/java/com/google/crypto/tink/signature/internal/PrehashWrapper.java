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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.Prehash;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.internal.Util;
import java.security.GeneralSecurityException;

/**
 * Provides a method "wrap", creating a {@link Prehash} from a keyset.
 *
 * <p>The returned primitive computes prehash values with the primary key of the keyset. All enabled
 * keys of the keyset must have an ID requirement, so that the computed prehash values identify the
 * key which has to be used to sign them.
 */
public final class PrehashWrapper {

  private static class PrehashWithId {
    PrehashWithId(Prehash prehash, int id) {
      this.prehash = prehash;
      this.id = id;
    }

    final Prehash prehash;
    final int id;
  }

  private static class PrehashImpl implements Prehash {
    private final PrehashWithId primary;
    private final MonitoringClient.Logger logger;

    PrehashImpl(PrehashWithId primary, MonitoringClient.Logger logger) {
      this.primary = primary;
      this.logger = logger;
    }

    @Override
    public byte[] compute(final byte[] data) throws GeneralSecurityException {
      try {
        byte[] output = primary.prehash.compute(data);
        logger.log(primary.id, data.length);
        return output;
      } catch (GeneralSecurityException e) {
        logger.logFailure();
        throw e;
      }
    }
  }

  public static Prehash wrap(
      KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<Prehash> factory)
      throws GeneralSecurityException {
    if (!Util.hasEnabledPrimaryKey(keysetHandle)) {
      throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
    }
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)
          && entry.getKey().getIdRequirementOrNull() == null) {
        throw new GeneralSecurityException(
            "Prehash does not support keys without ID requirement, found one with ID "
                + entry.getId());
      }
    }
    MonitoringClient.Logger logger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger = client.createLogger(keysetHandle, annotations, "prehash", "compute");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new PrehashImpl(
        new PrehashWithId(
            factory.create(keysetHandle.getPrimary()), keysetHandle.getPrimary().getId()),
        logger);
  }

  private PrehashWrapper() {}
}
