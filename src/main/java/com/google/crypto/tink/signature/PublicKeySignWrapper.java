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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringKeysetInfo;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveSet;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.signature.internal.LegacyFullSign;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<PublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
public class PublicKeySignWrapper implements PrimitiveWrapper<PublicKeySign, PublicKeySign> {

  private static final PublicKeySignWrapper WRAPPER = new PublicKeySignWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, PublicKeySign>
      LEGACY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullSign::create, LegacyProtoKey.class, PublicKeySign.class);

  private static class PublicKeySignWithId {
    public PublicKeySignWithId(PublicKeySign publicKeySign, int id) {
      this.publicKeySign = publicKeySign;
      this.id = id;
    }

    public final PublicKeySign publicKeySign;
    public final int id;
  }

  private static class WrappedPublicKeySign implements PublicKeySign {

    private final PublicKeySignWithId primary;

    private final MonitoringClient.Logger logger;

    public WrappedPublicKeySign(PublicKeySignWithId primary, MonitoringClient.Logger logger) {
      this.primary = primary;
      this.logger = logger;
    }

    @Override
    public byte[] sign(final byte[] data) throws GeneralSecurityException {
      try {
        byte[] output = primary.publicKeySign.sign(data);
        logger.log(primary.id, data.length);
        return output;
      } catch (GeneralSecurityException e) {
        logger.logFailure();
        throw e;
      }
    }
  }

  PublicKeySignWrapper() {}

  @Override
  public PublicKeySign wrap(final PrimitiveSet<PublicKeySign> primitives) {
    MonitoringClient.Logger logger;
    if (primitives.hasAnnotations()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
      logger = client.createLogger(keysetInfo, "public_key_sign", "sign");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedPublicKeySign(
        new PublicKeySignWithId(
            primitives.getPrimary().getFullPrimitive(), primitives.getPrimary().getKeyId()),
        logger);
  }

  @Override
  public Class<PublicKeySign> getPrimitiveClass() {
    return PublicKeySign.class;
  }

  @Override
  public Class<PublicKeySign> getInputPrimitiveClass() {
    return PublicKeySign.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeySign}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code PublicKeySignWrapper} to the provided
   * {@code PrimitiveRegistry#Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
