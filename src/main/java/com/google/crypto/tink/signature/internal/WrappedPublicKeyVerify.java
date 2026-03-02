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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.signature.SignaturePublicKey;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/** Provides a method "create", creating a public key verify from a keyset. */
public final class WrappedPublicKeyVerify {

  private static class PublicKeyVerifyWithId {
    PublicKeyVerifyWithId(PublicKeyVerify publicKeyVerify, int id) {
      this.publicKeyVerify = publicKeyVerify;
      this.id = id;
    }

    final PublicKeyVerify publicKeyVerify;
    final int id;
  }

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof SignaturePublicKey) {
      return ((SignaturePublicKey) key).getOutputPrefix();
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

  private static class PublicKeyVerifyImpl implements PublicKeyVerify {
    private final PrefixMap<PublicKeyVerifyWithId> allPublicKeyVerifys;
    private final MonitoringClient.Logger monitoringLogger;

    PublicKeyVerifyImpl(
        PrefixMap<PublicKeyVerifyWithId> allPublicKeyVerifys,
        MonitoringClient.Logger monitoringLogger) {
      this.allPublicKeyVerifys = allPublicKeyVerifys;
      this.monitoringLogger = monitoringLogger;
    }

    @Override
    public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
      for (PublicKeyVerifyWithId publicKeyVerifyWithId :
          allPublicKeyVerifys.getAllWithMatchingPrefix(signature)) {
        try {
          publicKeyVerifyWithId.publicKeyVerify.verify(signature, data);
          monitoringLogger.log(publicKeyVerifyWithId.id, data.length);
          // If there is no exception, the signature is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored
        }
      }
      monitoringLogger.logFailure();
      throw new GeneralSecurityException("invalid signature");
    }
  }

  public static PublicKeyVerify create(
      KeysetHandleInterface keysetHandle,
      PrimitiveWrapper.PrimitiveFactory<PublicKeyVerify> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<PublicKeyVerifyWithId> builder = new PrefixMap.Builder<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        PublicKeyVerify publicKeyVerify = factory.create(entry);
        builder.put(
            getOutputPrefix(entry.getKey()),
            new PublicKeyVerifyWithId(publicKeyVerify, entry.getId()));
      }
    }
    MonitoringClient.Logger logger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger = client.createLogger(keysetHandle, annotations, "public_key_verify", "verify");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new PublicKeyVerifyImpl(builder.build(), logger);
  }

  private WrappedPublicKeyVerify() {}
}
