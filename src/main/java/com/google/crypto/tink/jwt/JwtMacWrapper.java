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
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * JwtMacWrapper is the implementation of {@link PrimitiveWrapper} for the {@link JwtMac} primitive.
 */
class JwtMacWrapper implements PrimitiveWrapper<JwtMac, JwtMac> {
  private static class JwtMacWithId {
    JwtMacWithId(JwtMac jwtMac, int id) {
      this.jwtMac = jwtMac;
      this.id = id;
    }

    final JwtMac jwtMac;
    final int id;
  }

  private static final JwtMacWrapper WRAPPER = new JwtMacWrapper();

  private static void validate(PrimitiveSet<JwtMac> primitiveSet) throws GeneralSecurityException {
    if (primitiveSet.getKeysetHandle().getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedJwtMac implements JwtMac {
    @SuppressWarnings("Immutable")
    private final JwtMacWithId primary;

    @SuppressWarnings("Immutable") // We do not mutate the primitive set.
    private final List<JwtMacWithId> allMacs;

    @SuppressWarnings("Immutable")
    private final MonitoringClient.Logger computeLogger;

    @SuppressWarnings("Immutable")
    private final MonitoringClient.Logger verifyLogger;

    private WrappedJwtMac(
        JwtMacWithId primary,
        List<JwtMacWithId> allMacs,
        MonitoringClient.Logger computeLogger,
        MonitoringClient.Logger verifyLogger) {
      this.primary = primary;
      this.allMacs = allMacs;
      this.computeLogger = computeLogger;
      this.verifyLogger = verifyLogger;
    }

    @Override
    public String computeMacAndEncode(RawJwt token) throws GeneralSecurityException {
      try {
        String result = primary.jwtMac.computeMacAndEncode(token);
        computeLogger.log(primary.id, 1);
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
      for (JwtMacWithId macAndId : allMacs) {
        try {
          VerifiedJwt result = macAndId.jwtMac.verifyMacAndDecode(compact, validator);
          verifyLogger.log(macAndId.id, 1);
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
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    List<JwtMacWithId> allMacs = new ArrayList<>(keysetHandle.size());
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      JwtMac jwtMac = primitives.getPrimitiveForEntry(entry);
      allMacs.add(new JwtMacWithId(jwtMac, entry.getId()));
    }
    MonitoringClient.Logger computeLogger;
    MonitoringClient.Logger verifyLogger;
    if (!primitives.getAnnotations().isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      KeysetHandleInterface keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
      computeLogger =
          client.createLogger(keysetInfo, primitives.getAnnotations(), "jwtmac", "compute");
      verifyLogger =
          client.createLogger(keysetInfo, primitives.getAnnotations(), "jwtmac", "verify");
    } else {
      computeLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      verifyLogger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    JwtMac primaryMac = primitives.getPrimitiveForEntry(keysetHandle.getPrimary());

    return new WrappedJwtMac(
        new JwtMacWithId(primaryMac, keysetHandle.getPrimary().getId()),
        allMacs,
        computeLogger,
        verifyLogger);
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
