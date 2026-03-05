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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.hybrid.HybridPrivateKey;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveWrapper.PrimitiveFactory;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<HybridDecrypt>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To decrypt, the
 * primitive uses the prefix of the ciphertext to efficiently select the right key in the set. If
 * the keys associated with the prefix do not work, the primitive tries all keys with {@link
 * com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class WrappedHybridDecrypt {
  private static class HybridDecryptWithId {
    public HybridDecryptWithId(HybridDecrypt hybridDecrypt, int id) {
      this.hybridDecrypt = hybridDecrypt;
      this.id = id;
    }

    public final HybridDecrypt hybridDecrypt;
    public final int id;
  }

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof HybridPrivateKey) {
      return ((HybridPrivateKey) key).getOutputPrefix();
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

  private static class WrappedHybridDecryptImpl implements HybridDecrypt {
    private final PrefixMap<HybridDecryptWithId> allHybridDecrypts;
    private final MonitoringClient.Logger decLogger;

    WrappedHybridDecryptImpl(
        PrefixMap<HybridDecryptWithId> allHybridDecrypts, MonitoringClient.Logger decLogger) {
      this.allHybridDecrypts = allHybridDecrypts;
      this.decLogger = decLogger;
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
        throws GeneralSecurityException {
      for (HybridDecryptWithId hybridDecryptWithId :
          allHybridDecrypts.getAllWithMatchingPrefix(ciphertext)) {
        try {
          byte[] result = hybridDecryptWithId.hybridDecrypt.decrypt(ciphertext, contextInfo);
          decLogger.log(hybridDecryptWithId.id, ciphertext.length);
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

  private WrappedHybridDecrypt() {}

  public static HybridDecrypt create(
      KeysetHandleInterface keysetHandle, PrimitiveFactory<HybridDecrypt> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<HybridDecryptWithId> builder = new PrefixMap.Builder<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        HybridDecrypt hybridDecrypt = factory.create(entry);
        builder.put(
            getOutputPrefix(entry.getKey()), new HybridDecryptWithId(hybridDecrypt, entry.getId()));
      }
    }
    MonitoringClient.Logger decLogger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      decLogger = client.createLogger(keysetHandle, annotations, "hybrid_decrypt", "decrypt");
    } else {
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedHybridDecryptImpl(builder.build(), decLogger);
  }
}
