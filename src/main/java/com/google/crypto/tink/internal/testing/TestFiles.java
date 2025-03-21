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

import java.io.FileNotFoundException;
import java.io.InputStream;

/** Helper functions for reading test files. */
public final class TestFiles {

  /** Provides an InputStream to a test file dependency. */
  public static InputStream openInputFile(String pathname) throws FileNotFoundException {
    return BuildDispatchedTestCode.openInputFile(pathname);
  }

  private TestFiles() {}
}
