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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.PrefixMap;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.MacKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/** Creates a ChunkedMac primitive from a keyset. */
public final class WrappedChunkedMac {

  private static Bytes getOutputPrefix(Key key) throws GeneralSecurityException {
    if (key instanceof MacKey) {
      return ((MacKey) key).getOutputPrefix();
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

  private static class WrappedChunkedMacVerification implements ChunkedMacVerification {
    private final List<ChunkedMacVerification> verifications;

    private WrappedChunkedMacVerification(List<ChunkedMacVerification> verificationEntries) {
      this.verifications = verificationEntries;
    }

    @Override
    public void update(ByteBuffer data) throws GeneralSecurityException {
      // We will need to be `reset()`ting this buffer due to potentially multiple reads from the
      // same data span in order to be consistent with the behaviour of ChunkedMacComputation
      // wrapper. That is, after the execution, user's buffer's `mark` is left unchanged, and its
      // `position` is equal to `limit` after we finished reading from the buffer. In order to
      // achieve that we `duplicate()` the given `data` buffer here and set `mark()`s on the cloned
      // buffer (note that the `duplicate()` method does not copy the underlying data).
      ByteBuffer clonedData = data.duplicate();
      clonedData.mark();
      for (ChunkedMacVerification entry : verifications) {
        clonedData.reset();
        entry.update(clonedData);
      }
      data.position(data.limit());
    }

    @Override
    public void verifyMac() throws GeneralSecurityException {
      GeneralSecurityException errorSink =
          new GeneralSecurityException("MAC verification failed for all suitable keys in keyset");
      for (ChunkedMacVerification entry : verifications) {
        try {
          entry.verifyMac();
          // If there is no exception, the MAC is valid and we can return.
          return;
        } catch (GeneralSecurityException e) {
          // Ignored as we want to continue verification with the remaining keys.
          errorSink.addSuppressed(e);
        }
      }
      // nothing works.
      throw errorSink;
    }
  }

  @Immutable
  private static class WrappedChunkedMacImpl implements ChunkedMac {
    private final PrefixMap<ChunkedMac> allChunkedMacs;

    private final ChunkedMac primaryChunkedMac;

    private WrappedChunkedMacImpl(
        PrefixMap<ChunkedMac> allChunkedMacs, ChunkedMac primaryChunkedMac) {
      this.allChunkedMacs = allChunkedMacs;
      this.primaryChunkedMac = primaryChunkedMac;
    }

    @Override
    public ChunkedMacComputation createComputation() throws GeneralSecurityException {
      return primaryChunkedMac.createComputation();
    }

    @Override
    public ChunkedMacVerification createVerification(final byte[] tag)
        throws GeneralSecurityException {
      List<ChunkedMacVerification> allVerifications = new ArrayList<>();
      for (ChunkedMac mac : allChunkedMacs.getAllWithMatchingPrefix(tag)) {
        allVerifications.add(mac.createVerification(tag));
      }
      return new WrappedChunkedMacVerification(allVerifications);
    }
  }

  public static ChunkedMac create(
      KeysetHandleInterface keysetHandle, PrimitiveWrapper.PrimitiveFactory<ChunkedMac> factory)
      throws GeneralSecurityException {
    KeysetHandleInterface.Entry primaryEntry = keysetHandle.getPrimary();
    if (primaryEntry == null) {
      throw new GeneralSecurityException("no primary in primitive set");
    }
    PrefixMap.Builder<ChunkedMac> allChunkedMacsBuilder = new PrefixMap.Builder<ChunkedMac>();
    for (int i = 0; i < keysetHandle.size(); i++) {
      KeysetHandleInterface.Entry entry = keysetHandle.getAt(i);
      if (entry.getStatus().equals(KeyStatus.ENABLED)) {
        ChunkedMac chunkedMac = factory.create(entry);
        allChunkedMacsBuilder.put(getOutputPrefix(entry.getKey()), chunkedMac);
      }
    }
    ChunkedMac primaryChunkedMac = factory.create(primaryEntry);

    return new WrappedChunkedMacImpl(allChunkedMacsBuilder.build(), primaryChunkedMac);
  }

  private WrappedChunkedMac() {}
}
