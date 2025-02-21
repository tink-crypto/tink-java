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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.daead.internal.LegacyFullDeterministicAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringKeysetInfo;
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
 * The implementation of {@code PrimitiveWrapper<DeterministicAead>}.
 *
 * <p>The created primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key. To decrypt, the primitive uses the prefix of the ciphertext to efficiently
 * select the right key in the set. If the keys associated with the prefix do not work, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class DeterministicAeadWrapper
    implements PrimitiveWrapper<DeterministicAead, DeterministicAead> {
  private static class DeterministicAeadWithId {
    public DeterministicAeadWithId(DeterministicAead daead, int id) {
      this.daead = daead;
      this.id = id;
    }

    public final DeterministicAead daead;
    public final int id;
  }

  private static final DeterministicAeadWrapper WRAPPER = new DeterministicAeadWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, DeterministicAead>
      LEGACY_FULL_DAEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullDeterministicAead::create, LegacyProtoKey.class, DeterministicAead.class);

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

  private static class WrappedDeterministicAead implements DeterministicAead {
    private final DeterministicAeadWithId primary;
    private final PrefixMap<DeterministicAeadWithId> allDaeads;
    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    public WrappedDeterministicAead(
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

  DeterministicAeadWrapper() {}

  @Override
  public DeterministicAead wrap(final PrimitiveSet<DeterministicAead> primitives)
      throws GeneralSecurityException {
    PrefixMap.Builder<DeterministicAeadWithId> builder = new PrefixMap.Builder<>();
    for (PrimitiveSet.Entry<DeterministicAead> entry : primitives.getAllInKeysetOrder()) {
      builder.put(
          getOutputPrefix(entry.getKey()),
          new DeterministicAeadWithId(entry.getFullPrimitive(), entry.getKeyId()));
    }
    MonitoringClient.Logger encLogger;
    MonitoringClient.Logger decLogger;
    if (!primitives.getAnnotations().isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
      encLogger = client.createLogger(keysetInfo, "daead", "encrypt");
      decLogger = client.createLogger(keysetInfo, "daead", "decrypt");
    } else {
      encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedDeterministicAead(
        new DeterministicAeadWithId(
            primitives.getPrimary().getFullPrimitive(), primitives.getPrimary().getKeyId()),
        builder.build(),
        encLogger,
        decLogger);
  }

  @Override
  public Class<DeterministicAead> getPrimitiveClass() {
    return DeterministicAead.class;
  }

  @Override
  public Class<DeterministicAead> getInputPrimitiveClass() {
    return DeterministicAead.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_DAEAD_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code DeterministicAeadWrapper} to the provided
   * {@code PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
