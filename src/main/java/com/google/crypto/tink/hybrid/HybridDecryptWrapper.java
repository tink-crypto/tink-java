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
package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.hybrid.internal.LegacyFullHybridDecrypt;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
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
public class HybridDecryptWrapper implements PrimitiveWrapper<HybridDecrypt, HybridDecrypt> {
  private static class HybridDecryptWithId {
    public HybridDecryptWithId(HybridDecrypt hybridDecrypt, int id) {
      this.hybridDecrypt = hybridDecrypt;
      this.id = id;
    }

    public final HybridDecrypt hybridDecrypt;
    public final int id;
  }

  private static final HybridDecryptWrapper WRAPPER = new HybridDecryptWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, HybridDecrypt>
      LEGACY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullHybridDecrypt::create, LegacyProtoKey.class, HybridDecrypt.class);

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

  private static class WrappedHybridDecrypt implements HybridDecrypt {
    private final PrefixMap<HybridDecryptWithId> allHybridDecrypts;
    private final MonitoringClient.Logger decLogger;

    public WrappedHybridDecrypt(
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

  HybridDecryptWrapper() {}

  @Override
  public HybridDecrypt wrap(
      final PrimitiveSet<HybridDecrypt> primitives, PrimitiveFactory<HybridDecrypt> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<HybridDecryptWithId> builder = new PrefixMap.Builder<>();
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      HybridDecrypt hybridDecrypt = factory.create(entry);
      builder.put(
          getOutputPrefix(entry.getKey()), new HybridDecryptWithId(hybridDecrypt, entry.getId()));
    }
    MonitoringClient.Logger decLogger;
    if (!primitives.getAnnotations().isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      decLogger =
          client.createLogger(
              keysetHandle, primitives.getAnnotations(), "hybrid_decrypt", "decrypt");
    } else {
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedHybridDecrypt(builder.build(), decLogger);
  }

  @Override
  public Class<HybridDecrypt> getPrimitiveClass() {
    return HybridDecrypt.class;
  }

  @Override
  public Class<HybridDecrypt> getInputPrimitiveClass() {
    return HybridDecrypt.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link HybridDecrypt}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code HybridDecryptWrapper} to the provided
   * {@code PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
