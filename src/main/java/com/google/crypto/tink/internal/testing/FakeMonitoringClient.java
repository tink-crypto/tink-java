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

package com.google.crypto.tink.internal.testing;

import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * Fake MonitoringClient.
 *
 * <p>It logs all log and logFailure calls of its logger objects into two lists that can be
 * retrieved later.
 */
public final class FakeMonitoringClient implements MonitoringClient {

  /** LogEntry */
  public static final class LogEntry {
    private final KeysetHandleInterface keysetInfo;
    private final KeysetHandleInterface.Entry keyInfo;
    private final MonitoringAnnotations annotations;
    private final String primitive;
    private final String api;
    private final int keyId;
    private final long numBytesAsInput;

    private LogEntry(
        KeysetHandleInterface keysetInfo,
        KeysetHandleInterface.Entry keyInfo,
        MonitoringAnnotations annotations,
        String primitive,
        String api,
        int keyId,
        long numBytesAsInput) {
      this.keysetInfo = keysetInfo;
      this.keyInfo = keyInfo;
      this.annotations = annotations;
      this.primitive = primitive;
      this.api = api;
      this.keyId = keyId;
      this.numBytesAsInput = numBytesAsInput;
    }

    public KeysetHandleInterface getKeysetInfo() {
      return keysetInfo;
    }

    public KeysetHandleInterface.Entry getKeyInfo() {
      return keyInfo;
    }

    public String getPrimitive() {
      return primitive;
    }

    public String getApi() {
      return api;
    }

    public int getKeyId() {
      return keyId;
    }

    public long getNumBytesAsInput() {
      return numBytesAsInput;
    }

    public MonitoringAnnotations getAnnotations() {
      return annotations;
    }
  }

  /** LogFailureEntry */
  public static final class LogFailureEntry {
    private final String primitive;
    private final String api;
    private final KeysetHandleInterface keysetInfo;
    private final MonitoringAnnotations annotations;

    private LogFailureEntry(
        KeysetHandleInterface keysetInfo,
        MonitoringAnnotations annotations,
        String primitive,
        String api) {
      this.keysetInfo = keysetInfo;
      this.annotations = annotations;
      this.primitive = primitive;
      this.api = api;
    }

    public String getPrimitive() {
      return primitive;
    }

    public String getApi() {
      return api;
    }

    public KeysetHandleInterface getKeysetInfo() {
      return keysetInfo;
    }

    public MonitoringAnnotations getAnnotations() {
      return annotations;
    }
  }

  /** LogEntry */
  public static final class LogKeyExportEntry {
    private final KeysetHandleInterface keysetInfo;
    private final KeysetHandleInterface.Entry keyInfo;
    private final MonitoringAnnotations annotations;
    private final String primitive;
    private final String api;
    private final int keyId;

    private LogKeyExportEntry(
        KeysetHandleInterface keysetInfo,
        KeysetHandleInterface.Entry keyInfo,
        MonitoringAnnotations annotations,
        String primitive,
        String api,
        int keyId) {
      this.keysetInfo = keysetInfo;
      this.keyInfo = keyInfo;
      this.annotations = annotations;
      this.primitive = primitive;
      this.api = api;
      this.keyId = keyId;
    }

    public KeysetHandleInterface getKeysetInfo() {
      return keysetInfo;
    }

    public KeysetHandleInterface.Entry getKeyInfo() {
      return keyInfo;
    }

    public String getPrimitive() {
      return primitive;
    }

    public String getApi() {
      return api;
    }

    public int getKeyId() {
      return keyId;
    }

    public MonitoringAnnotations getAnnotations() {
      return annotations;
    }
  }

  private final List<LogEntry> logEntries = new ArrayList<>();
  private final List<LogFailureEntry> logFailureEntries = new ArrayList<>();
  private final List<LogKeyExportEntry> logKeyExportEntries = new ArrayList<>();

  private synchronized void addLogEntry(LogEntry entry) {
    logEntries.add(entry);
  }

  private synchronized void addLogFailureEntry(LogFailureEntry entry) {
    logFailureEntries.add(entry);
  }

  private synchronized void addLogKeyExportEntry(LogKeyExportEntry entry) {
    logKeyExportEntries.add(entry);
  }

  private final class Logger implements MonitoringClient.Logger {
    private final KeysetHandleInterface keysetInfo;
    private final MonitoringAnnotations annotations;
    private final HashMap<Integer, KeysetHandleInterface.Entry> entries;
    private final String primitive;
    private final String api;

    @Override
    public void log(int keyId, long numBytesAsInput) {
      if (!entries.containsKey(keyId)) {
        throw new IllegalStateException("keyId not found in keysetInfo: " + keyId);
      }
      addLogEntry(
          new LogEntry(
              keysetInfo, entries.get(keyId), annotations, primitive, api, keyId, numBytesAsInput));
    }

    @Override
    public void logFailure() {
      addLogFailureEntry(new LogFailureEntry(keysetInfo, annotations, primitive, api));
    }

    @Override
    public void logKeyExport(int keyId) {
      if (!entries.containsKey(keyId)) {
        throw new IllegalStateException("keyId not found in keysetInfo: " + keyId);
      }
      addLogKeyExportEntry(
          new LogKeyExportEntry(
              keysetInfo, entries.get(keyId), annotations, primitive, api, keyId));
    }

    private Logger(
        KeysetHandleInterface keysetInfo,
        MonitoringAnnotations annotations,
        String primitive,
        String api) {
      this.keysetInfo = keysetInfo;
      this.primitive = primitive;
      this.annotations = annotations;
      this.api = api;
      entries = new HashMap<>();
      for (int i = 0; i < keysetInfo.size(); i++) {
        KeysetHandleInterface.Entry entry = keysetInfo.getAt(i);
        entries.put(entry.getId(), entry);
      }
    }
  }

  public FakeMonitoringClient() {
  }

  @Override
  public Logger createLogger(
      KeysetHandleInterface keysetInfo,
      MonitoringAnnotations annotations,
      String primitive,
      String api) {
    return new Logger(keysetInfo, annotations, primitive, api);
  }

  /** Clears all log and log failure entries. */
  public synchronized void clear() {
    logEntries.clear();
    logFailureEntries.clear();
    logKeyExportEntries.clear();
  }

  /** Returns all log entries. */
  public synchronized List<LogEntry> getLogEntries() {
    return Collections.unmodifiableList(logEntries);
  }

  /** Returns all log failure entries. */
  public synchronized List<LogFailureEntry> getLogFailureEntries() {
    return Collections.unmodifiableList(logFailureEntries);
  }

  /** Returns all log key export entries. */
  public synchronized List<LogKeyExportEntry> getLogKeyExportEntries() {
    return Collections.unmodifiableList(logKeyExportEntries);
  }
}
