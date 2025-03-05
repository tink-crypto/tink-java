// Copyright 2021 Google LLC
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

/** The implementation of {@code PrimitiveWrapper<JwtPublicKeyVerify>}. */
class JwtPublicKeyVerifyWrapper
    implements PrimitiveWrapper<JwtPublicKeyVerify, JwtPublicKeyVerify> {
  private static class JwtPublicKeyVerifyWithId {
    JwtPublicKeyVerifyWithId(JwtPublicKeyVerify verify, int id) {
      this.verify = verify;
      this.id = id;
    }

    final JwtPublicKeyVerify verify;
    final int id;
  }

  private static final JwtPublicKeyVerifyWrapper WRAPPER = new JwtPublicKeyVerifyWrapper();

  @Immutable
  private static class WrappedJwtPublicKeyVerify implements JwtPublicKeyVerify {

    @SuppressWarnings("Immutable")
    private final MonitoringClient.Logger logger;

    @SuppressWarnings("Immutable")
    private final List<JwtPublicKeyVerifyWithId> allVerifiers;

    public WrappedJwtPublicKeyVerify(
        MonitoringClient.Logger logger, List<JwtPublicKeyVerifyWithId> allVerifiers) {
      this.logger = logger;
      this.allVerifiers = allVerifiers;
    }

    @Override
    public VerifiedJwt verifyAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      GeneralSecurityException interestingException = null;
      for (JwtPublicKeyVerifyWithId verifier : allVerifiers) {
        try {
          VerifiedJwt result = verifier.verify.verifyAndDecode(compact, validator);
          logger.log(verifier.id, 1);
          return result;
        } catch (GeneralSecurityException e) {
          if (e instanceof JwtInvalidException) {
            // Keep this exception so that we are able to throw a meaningful message in the end
            interestingException = e;
          }
          // Ignored as we want to continue verification with other raw keys.
        }
      }
      logger.logFailure();
      if (interestingException != null) {
        throw interestingException;
      }
      throw new GeneralSecurityException("invalid JWT");
    }
  }

  @Override
  public JwtPublicKeyVerify wrap(final PrimitiveSet<JwtPublicKeyVerify> primitives)
      throws GeneralSecurityException {
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    List<JwtPublicKeyVerifyWithId> allVerifiers = new ArrayList<>(keysetHandle.size());
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      allVerifiers.add(
          new JwtPublicKeyVerifyWithId(primitives.getPrimitiveForEntry(entry), entry.getId()));
    }
    MonitoringClient.Logger logger;
    if (!primitives.getAnnotations().isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger =
          client.createLogger(keysetHandle, primitives.getAnnotations(), "jwtverify", "verify");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }

    return new WrappedJwtPublicKeyVerify(logger, allVerifiers);
  }

  @Override
  public Class<JwtPublicKeyVerify> getPrimitiveClass() {
    return JwtPublicKeyVerify.class;
  }

  @Override
  public Class<JwtPublicKeyVerify> getInputPrimitiveClass() {
    return JwtPublicKeyVerify.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link JwtPublicKeyVerify}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
  }
}
