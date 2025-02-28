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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeysetHandleInterface;
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
import com.google.crypto.tink.signature.internal.LegacyFullVerify;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<DeterministicAead>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set. If
 * there is no key associated with the prefix or if the keys associated with the prefix do not work,
 * the primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
public class PublicKeyVerifyWrapper implements PrimitiveWrapper<PublicKeyVerify, PublicKeyVerify> {
  private static class PublicKeyVerifyWithId {
    public PublicKeyVerifyWithId(PublicKeyVerify publicKeyVerify, int id) {
      this.publicKeyVerify = publicKeyVerify;
      this.id = id;
    }

    public final PublicKeyVerify publicKeyVerify;
    public final int id;
  }

  private static final PublicKeyVerifyWrapper WRAPPER = new PublicKeyVerifyWrapper();
  private static final PrimitiveConstructor<LegacyProtoKey, PublicKeyVerify>
      LEGACY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              LegacyFullVerify::create, LegacyProtoKey.class, PublicKeyVerify.class);

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof SignaturePublicKey) {
      return ((SignaturePublicKey) key).getOutputPrefix();
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

  private static class WrappedPublicKeyVerify implements PublicKeyVerify {
    private final PrefixMap<PublicKeyVerifyWithId> allPublicKeyVerifys;

    private final MonitoringClient.Logger monitoringLogger;

    public WrappedPublicKeyVerify(
        PrefixMap<PublicKeyVerifyWithId> allPublicKeyVerifys,
        MonitoringClient.Logger monitoringLogger) {
      this.allPublicKeyVerifys = allPublicKeyVerifys;
      this.monitoringLogger = monitoringLogger;
    }

    @Override
    public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
      for (PublicKeyVerifyWithId publicKeyVerifyWithId :
          allPublicKeyVerifys.getAllWithMatchingPrefix(signature)) {
        try {
          publicKeyVerifyWithId.publicKeyVerify.verify(signature, data);
          monitoringLogger.log(publicKeyVerifyWithId.id, data.length);
          // If there is no exception, the signature is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored
        }
      }
      monitoringLogger.logFailure();
      throw new GeneralSecurityException("invalid signature");
    }
  }

  @Override
  public PublicKeyVerify wrap(final PrimitiveSet<PublicKeyVerify> primitives)
      throws GeneralSecurityException {
    PrefixMap.Builder<PublicKeyVerifyWithId> builder = new PrefixMap.Builder<>();
    KeysetHandleInterface keysetHandle = primitives.getKeysetHandle();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      PublicKeyVerify publicKeyVerify = primitives.getPrimitiveForEntry(entry);
      builder.put(
          getOutputPrefix(entry.getKey()),
          new PublicKeyVerifyWithId(publicKeyVerify, entry.getId()));
    }
    MonitoringClient.Logger logger;
    if (!primitives.getAnnotations().isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
      logger =
          client.createLogger(
              keysetInfo, primitives.getAnnotations(), "public_key_verify", "verify");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new WrappedPublicKeyVerify(builder.build(), logger);
  }

  @Override
  public Class<PublicKeyVerify> getPrimitiveClass() {
    return PublicKeyVerify.class;
  }

  @Override
  public Class<PublicKeyVerify> getInputPrimitiveClass() {
    return PublicKeyVerify.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeyVerify}
   * argument.
   */
  static void register() throws GeneralSecurityException {
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_PRIMITIVE_CONSTRUCTOR);
  }

  /**
   * registerToInternalPrimitiveRegistry is a non-public method (it takes an argument of an
   * internal-only type) registering an instance of {@code PublicKeyVerifyWrapper} to the provided
   * {@code PrimitiveRegistry#Builder}.
   */
  public static void registerToInternalPrimitiveRegistry(
      PrimitiveRegistry.Builder primitiveRegistryBuilder) throws GeneralSecurityException {
    primitiveRegistryBuilder.registerPrimitiveWrapper(WRAPPER);
  }
}
