// Copyright 2024 Google LLC
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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Takes an arbitrary raw PublicKeyVerify from the registry and creates a full PublicKeyVerify out
 * of it.
 */
@Immutable
public final class LegacyFullVerify implements PublicKeyVerify {
  /** Creates the full primitive corresponding to the key. */
  public static PublicKeyVerify create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyManager<PublicKeyVerify> manager =
        KeyManagerRegistry.globalInstance()
            .getKeyManager(protoKeySerialization.getTypeUrl(), PublicKeyVerify.class);

    PublicKeyVerify rawVerifier = manager.getPrimitive(protoKeySerialization.getValue());
    return new LegacyFullVerify(
        rawVerifier,
        getOutputPrefix(protoKeySerialization),
        getMessageSuffix(protoKeySerialization));
  }

  static byte[] getOutputPrefix(ProtoKeySerialization key) throws GeneralSecurityException {
    switch (key.getOutputPrefixType()) {
      case LEGACY: // fall through
      case CRUNCHY:
        return OutputPrefixUtil.getLegacyOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
      case TINK:
        return OutputPrefixUtil.getTinkOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
      case RAW:
        return OutputPrefixUtil.EMPTY_PREFIX.toByteArray();
      default:
        throw new GeneralSecurityException("unknown output prefix type");
    }
  }

  static byte[] getMessageSuffix(ProtoKeySerialization key) {
    if (key.getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
      return new byte[] {0};
    }
    return new byte[0];
  }

  private LegacyFullVerify(PublicKeyVerify rawVerifier, byte[] outputPrefix, byte[] messageSuffix) {
    this.rawVerifier = rawVerifier;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  @SuppressWarnings("Immutable")
  private final PublicKeyVerify rawVerifier;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @Override
  public void verify(byte[] signature, byte[] data) throws GeneralSecurityException {
    if (outputPrefix.length == 0 && messageSuffix.length == 0) {
      rawVerifier.verify(signature, data);
      return;
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    byte[] dataCopy = data;
    if (messageSuffix.length != 0) {
      dataCopy = Bytes.concat(data, messageSuffix);
    }
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
    rawVerifier.verify(signatureNoPrefix, dataCopy);
  }
}
