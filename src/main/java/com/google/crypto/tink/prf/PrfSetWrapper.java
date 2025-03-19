// Copyright 2020 Google LLC
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
package com.google.crypto.tink.prf;

import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.prf.internal.LegacyFullPrf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

/**
 * PrfSetWrapper is the implementation of PrimitiveWrapper for the PrfSet primitive.
 *
 * <p>The returned primitive has instances of {@code Prf} for each key in the KeySet. The individual
 * Prf instances can then be used to compute psuedo-random sequences from the underlying key.
 */
@Immutable
public class PrfSetWrapper implements PrimitiveWrapper<Prf, PrfSet> {

  private static final PrfSetWrapper WRAPPER = new PrfSetWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, Prf>
      LEGACY_FULL_PRF_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(LegacyFullPrf::create, LegacyProtoKey.class, Prf.class);

  private static class WrappedPrfSet extends PrfSet {
    // This map is constructed using Collections.unmodifiableMap
    @SuppressWarnings("Immutable")
    private final Map<Integer, Prf> keyIdToPrfMap;

    private final int primaryKeyId;

    @Immutable
    private static class PrfWithMonitoring implements Prf {
      private final Prf prf;
      private final int keyId;

      @SuppressWarnings("Immutable")
      private final MonitoringClient.Logger logger;

      @Override
      public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
        try {
          byte[] output = prf.compute(input, outputLength);
          logger.log(keyId, input.length);
          return output;
        } catch (GeneralSecurityException e) {
          logger.logFailure();
          throw e;
        }
      }

      public PrfWithMonitoring(Prf prf, int keyId, MonitoringClient.Logger logger) {
        this.prf = prf;
        this.keyId = keyId;
        this.logger = logger;
      }
    }

    private WrappedPrfSet(Map<Integer, Prf> keyIdToPrfMap, int primaryKeyId) {
      this.keyIdToPrfMap = keyIdToPrfMap;
      this.primaryKeyId = primaryKeyId;
    }

    @Override
    public int getPrimaryId() {
      return primaryKeyId;
    }

    @Override
    public Map<Integer, Prf> getPrfs() throws GeneralSecurityException {
      return keyIdToPrfMap;
    }
  }

  @Override
  public PrfSet wrap(
      PrimitiveSet<Prf> set, MonitoringAnnotations annotations, PrimitiveFactory<Prf> factory)
      throws GeneralSecurityException {
    KeysetHandleInterface keysetHandle = set.getKeysetHandle();
    MonitoringClient.Logger logger;
    if (!annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger = client.createLogger(keysetHandle, annotations, "prf", "compute");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }

    Map<Integer, Prf> mutablePrfMap = new HashMap<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getKey() instanceof LegacyProtoKey) {
        LegacyProtoKey legacyProtoKey = (LegacyProtoKey) entry.getKey();
        if (legacyProtoKey.getOutputPrefix().size() != 0) {
          throw new GeneralSecurityException(
              "Cannot build PrfSet with keys with non-empty output prefix");
        }
      }
      Prf prf = factory.create(entry);
      // Likewise, the key IDs of the PrfSet passed
      mutablePrfMap.put(
          entry.getId(), new WrappedPrfSet.PrfWithMonitoring(prf, entry.getId(), logger));
    }
    return new WrappedPrfSet(mutablePrfMap, keysetHandle.getPrimary().getId());
  }

  @Override
  public Class<PrfSet> getPrimitiveClass() {
    return PrfSet.class;
  }

  @Override
  public Class<Prf> getInputPrimitiveClass() {
    return Prf.class;
  }

  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_FULL_PRF_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code PrfSetWrapper} to the provided {@code
   * PrimitiveRegistry.Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
