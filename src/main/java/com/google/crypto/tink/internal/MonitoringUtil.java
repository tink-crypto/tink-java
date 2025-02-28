// Copyright 2022 Google LLC
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

package com.google.crypto.tink.internal;

import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Some util functions needed to add monitoring to the Primitives. */
public final class MonitoringUtil {

  private static class DoNothingLogger implements MonitoringClient.Logger {
    @Override
    public void log(int keyId, long numBytesAsInput) {}

    @Override
    public void logFailure() {}
  }

  public static final MonitoringClient.Logger DO_NOTHING_LOGGER = new DoNothingLogger();

  public static <P> MonitoringKeysetInfo getMonitoringKeysetInfo(PrimitiveSet<P> primitiveSet) {
    MonitoringKeysetInfo.Builder builder = MonitoringKeysetInfo.newBuilder();
    KeysetHandleInterface handle = primitiveSet.getKeysetHandle();
    for (int i = 0; i < handle.size(); i++) {
      KeysetHandleInterface.Entry entry = handle.getAt(i);
      builder.addEntry(entry.getKey(), entry.getStatus(), entry.getId());
    }
    @Nullable PrimitiveSet.Entry<P> primary = primitiveSet.getPrimary();
    if (primary != null) {
      builder.setPrimaryKeyId(primitiveSet.getPrimary().getId());
    }
    try {
      return builder.build();
    } catch (GeneralSecurityException e) {
      // This shouldn't happen, since for PrimitiveSets, the primary's key id is always in the
      // entries list.
      throw new IllegalStateException(e);
    }
  }

  private MonitoringUtil() {}
}
