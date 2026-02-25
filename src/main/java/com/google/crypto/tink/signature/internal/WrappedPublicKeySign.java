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

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import java.security.GeneralSecurityException;

/** Provides a method "create", creating a public key sign from a keyset. */
public final class WrappedPublicKeySign {

  private static class PublicKeySignWithId {
    PublicKeySignWithId(PublicKeySign publicKeySign, int id) {
      this.publicKeySign = publicKeySign;
      this.id = id;
    }

    final PublicKeySign publicKeySign;
    final int id;
  }

  private static class PublicKeySignImpl implements PublicKeySign {

    private final PublicKeySignWithId primary;
    private final MonitoringClient.Logger logger;

    PublicKeySignImpl(PublicKeySignWithId primary, MonitoringClient.Logger logger) {
      this.primary = primary;
      this.logger = logger;
    }

    @Override
    public byte[] sign(final byte[] data) throws GeneralSecurityException {
      try {
        byte[] output = primary.publicKeySign.sign(data);
        logger.log(primary.id, data.length);
        return output;
      } catch (GeneralSecurityException e) {
        logger.logFailure();
        throw e;
      }
    }
  }

  public static PublicKeySign create(
      KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<PublicKeySign> factory)
      throws GeneralSecurityException {
    MonitoringClient.Logger logger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger = client.createLogger(keysetHandle, annotations, "public_key_sign", "sign");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new PublicKeySignImpl(
        new PublicKeySignWithId(
            factory.create(keysetHandle.getPrimary()), keysetHandle.getPrimary().getId()),
        logger);
  }

  private WrappedPublicKeySign() {}
}
