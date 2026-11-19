// Copyright 2026 Google LLC
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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.SignPrehash;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.internal.Util;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides a method "wrap", creating a {@link SignPrehash} from a keyset.
 *
 * <p>The returned primitive signs a prehash value with the enabled key whose ID is encoded in the
 * prefix of the prehash value (see {@link PrehashFormat}), which is not necessarily the primary
 * key. That is, the side computing the prehash value selects the key, and the signing side follows
 * that choice. This makes keysets rotatable: a newly added key can sign as soon as it is enabled,
 * and an old key keeps signing prehash values which are still in flight until it is disabled.
 *
 * <p>All enabled keys of the keyset must have an ID requirement.
 */
public final class SignPrehashWrapper {

  private static class SignPrehashWithId {
    SignPrehashWithId(SignPrehash signPrehash, int id) {
      this.signPrehash = signPrehash;
      this.id = id;
    }

    final SignPrehash signPrehash;
    final int id;
  }

  private static class SignPrehashImpl implements SignPrehash {
    private final Map<Integer, SignPrehashWithId> signers;
    private final MonitoringClient.Logger logger;

    SignPrehashImpl(Map<Integer, SignPrehashWithId> signers, MonitoringClient.Logger logger) {
      this.signers = signers;
      this.logger = logger;
    }

    private SignPrehashWithId getSigner(byte[] prehash) throws GeneralSecurityException {
      if (prehash.length < PrehashFormat.PREHASH_PREFIX_SIZE) {
        throw new GeneralSecurityException("Prehash is missing required prefix");
      }
      if (prehash[0] != PrehashFormat.PREHASH_START_BYTE) {
        throw new GeneralSecurityException("Prehash does not start with prehash prefix byte");
      }
      // The 4 bytes following the start byte contain the big-endian key ID.
      int keyId = ByteBuffer.wrap(prehash).getInt(1);
      SignPrehashWithId signer = signers.get(keyId);
      if (signer == null) {
        throw new GeneralSecurityException(
            "Could not find enabled prehash signing key with key ID " + keyId);
      }
      return signer;
    }

    @Override
    public byte[] sign(byte[] prehash) throws GeneralSecurityException {
      try {
        SignPrehashWithId signer = getSigner(prehash);
        // The full prehash value (including its prefix) is passed on, so the key specific
        // primitive can verify that the prefix matches its key.
        byte[] output = signer.signPrehash.sign(prehash);
        logger.log(signer.id, prehash.length);
        return output;
      } catch (GeneralSecurityException e) {
        logger.logFailure();
        throw e;
      }
    }
  }

  public static SignPrehash wrap(
      KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<SignPrehash> factory)
      throws GeneralSecurityException {
    // Signing does not single out the primary key, but a keyset without a valid primary key is
    // malformed.
    if (!Util.hasEnabledPrimaryKey(keysetHandle)) {
      throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
    }
    Map<Integer, SignPrehashWithId> signers = new HashMap<>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (!entry.getStatus().equals(KeyStatus.ENABLED)) {
        continue;
      }
      if (entry.getKey().getIdRequirementOrNull() == null) {
        throw new GeneralSecurityException(
            "SignPrehash does not support keys without ID requirement, found one with ID "
                + entry.getId());
      }
      signers.put(entry.getId(), new SignPrehashWithId(factory.create(entry), entry.getId()));
    }
    MonitoringClient.Logger logger;
    MonitoringAnnotations annotations =
        keysetHandle.getAnnotationsOrNull(MonitoringAnnotations.class);
    if (annotations != null && !annotations.isEmpty()) {
      MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
      logger = client.createLogger(keysetHandle, annotations, "prehash_signer", "sign");
    } else {
      logger = MonitoringUtil.DO_NOTHING_LOGGER;
    }
    return new SignPrehashImpl(signers, logger);
  }

  private SignPrehashWrapper() {}
}
