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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Mac;
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
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.mac.internal.LegacyFullMac;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/**
 * MacWrapper is the implementation of PrimitiveWrapper for the Mac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To compute a MAC tag,
 * it uses the primary key in the keyset, and prepends to the tag a certain prefix associated with
 * the primary key. To verify a tag, the primitive uses the prefix of the tag to efficiently select
 * the right key in the set. If the keys associated with the prefix do not validate the tag, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class MacWrapper implements PrimitiveWrapper<Mac, Mac> {
  private static class MacWithId {
    public MacWithId(Mac mac, int id) {
      this.mac = mac;
      this.id = id;
    }

    public final Mac mac;
    public final int id;
  }

  private static final MacWrapper WRAPPER = new MacWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Mac>
      LEGACY_FULL_MAC_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullMac::create, LegacyProtoKey.class, Mac.class);

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof MacKey) {
      return ((MacKey) key).getOutputPrefix();
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

  private static class WrappedMac implements Mac {
    private final MacWithId primary;
    private final PrefixMap<MacWithId> allMacs;
    private final MonitoringClient.Logger computeLogger;
    private final MonitoringClient.Logger verifyLogger;

    private WrappedMac(
        MacWithId primary,
        PrefixMap<MacWithId> allMacs,
        MonitoringClient.Logger computeLogger,
        MonitoringClient.Logger verifyLogger) {
      this.primary = primary;
      this.allMacs = allMacs;
      this.computeLogger = computeLogger;
      this.verifyLogger = verifyLogger;
    }

    @Override
    public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
      try {
        byte[] output = primary.mac.computeMac(data);
        computeLogger.log(primary.id, data.length);
        return output;
      } catch (GeneralSecurityException e) {
        computeLogger.logFailure();
        throw e;
      }
    }

    @Override
    public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
      for (MacWithId macWithId : allMacs.getAllWithMatchingPrefix(mac)) {
        try {
          macWithId.mac.verifyMac(mac, data);
          verifyLogger.log(macWithId.id, data.length);
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored as we want to continue verification with the remaining keys.
        }
      }
      verifyLogger.logFailure();
      throw new GeneralSecurityException("invalid MAC");
    }
  }

  MacWrapper() {}

  @Override
  public Mac wrap(
      final PrimitiveSet<Mac> primitives,
      MonitoringAnnotations annotations,
      PrimitiveFactory<Mac> factory)
      throws GeneralSecurityException {
    PrefixMap.Builder<MacWithId> builder = new PrefixMap.Builder<>();
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      Mac mac = factory.create(entry);
      builder.put(getOutputPrefix(entry.getKey()), new MacWithId(mac, entry.getId()));
    }
    MonitoringClient.Logger computeLogger;
    MonitoringClient.Logger verifyLogger;
    if (!annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      computeLogger = client.createLogger(keysetHandle, annotations, "mac", "compute");
      verifyLogger = client.createLogger(keysetHandle, annotations, "mac", "verify");
    } else {
      computeLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      verifyLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    Mac primaryMac = factory.create(keysetHandle.getPrimary());
    return new WrappedMac(
        new MacWithId(primaryMac, keysetHandle.getPrimary().getId()),
        builder.build(),
        computeLogger,
        verifyLogger);
  }

  @Override
  public Class<Mac> getPrimitiveClass() {
    return Mac.class;
  }

  @Override
  public Class<Mac> getInputPrimitiveClass() {
    return Mac.class;
  }

  static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_MAC_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code MacWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
