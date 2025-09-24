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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.internal.testing;

//import androidx.test.platform.io.PlatformTestStorageRegistry;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 * Static testonly utility functions which need to be compiled with different code in Android and
 * Java.
 *
 * <p>This is the Android version. The Java code can be found in
 * src/main/java/com/google/crypto/tink/internal/testing/BuildDispatchedTestCode.java
 */
public final class BuildDispatchedTestCode {

  private BuildDispatchedTestCode() {}

  public static InputStream openInputFile(String pathname) throws FileNotFoundException {
    throw new UnsupportedOperationException("Not supported on OSS Android.");
  }

  public static void disableFlagsStateCheckingForTests() {}
}
