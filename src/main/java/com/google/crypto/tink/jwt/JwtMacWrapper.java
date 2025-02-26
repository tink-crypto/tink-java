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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringKeysetInfo;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * JwtMacWrapper is the implementation of {@link PrimitiveWrapper} for the {@link JwtMac} primitive.
 */
class JwtMacWrapper implements PrimitiveWrapper<JwtMac, JwtMac> {

  private static final JwtMacWrapper WRAPPER = new JwtMacWrapper();

  private static void validate(PrimitiveSet<JwtMac> primitiveSet) throws GeneralSecurityException {
    if (primitiveSet.getKeysetHandle().getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedJwtMac implements JwtMac {
    @SuppressWarnings("Immutable") // We do not mutate the primitive set.
    private final PrimitiveSet<JwtMac> primitives;

    @SuppressWarnings("Immutable")
    private final MonitoringClient.Logger computeLogger;

    @SuppressWarnings("Immutable")
    private final MonitoringClient.Logger verifyLogger;

    private WrappedJwtMac(PrimitiveSet<JwtMac> primitives) {
      this.primitives = primitives;
      if (!primitives.getAnnotations().isEmpty()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        this.computeLogger = client.createLogger(keysetInfo, "jwtmac", "compute");
        this.verifyLogger = client.createLogger(keysetInfo, "jwtmac", "verify");
      } else {
        this.computeLogger = MonitoringUtil.DO_NOTHING_LOGGER;
        this.verifyLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public String computeMacAndEncode(RawJwt token) throws GeneralSecurityException {
      try {
        KeysetHandleInterface.Entry primary = primitives.getKeysetHandle().getPrimary();
        JwtMac primaryJwtMac = primitives.getPrimitiveForEntry(primary);
        String result = primaryJwtMac.computeMacAndEncode(token);
        computeLogger.log(primary.getId(), 1);
        return result;
      } catch (GeneralSecurityException e) {
        computeLogger.logFailure();
        throw e;
      }
    }

    @Override
    public VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      GeneralSecurityException interestingException = null;
      KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
      for (int i = 0; i < keysetHandle.size(); i++) {
        KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
        JwtMac jwtMac = primitives.getPrimitiveForEntry(entry);
        try {
          VerifiedJwt result = jwtMac.verifyMacAndDecode(compact, validator);
          verifyLogger.log(entry.getId(), 1);
          return result;
        } catch (GeneralSecurityException e) {
          if (e instanceof JwtInvalidException) {
            // Keep this exception so that we are able to throw a meaningful message in the end
            interestingException = e;
          }
          // Ignored as we want to continue verification with other raw keys.
        }
      }
      verifyLogger.logFailure();
      if (interestingException != null) {
        throw interestingException;
      }
      throw new GeneralSecurityException("invalid MAC");
    }
  }

  JwtMacWrapper() {}

  @Override
  public JwtMac wrap(final PrimitiveSet<JwtMac> primitives) throws GeneralSecurityException {
    validate(primitives);
    return new WrappedJwtMac(primitives);
  }

  @Override
  public Class<JwtMac> getPrimitiveClass() {
    return JwtMac.class;
  }

  @Override
  public Class<JwtMac> getInputPrimitiveClass() {
    return JwtMac.class;
  }

 public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
  }
}
