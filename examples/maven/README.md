# Example Maven project using Tink

This directory contains a simple example Maven project which uses Tink.

One can build this by running `mvn package`.

Assuming that we have the `tink-1.18.0.jar` and `protobuf-java-4.32.1.jar`
available, we can then run it using:

`java -cp target/experimental-tink-app-1.0-SNAPSHOT.jar:tink-1.18.0.jar:protobuf-java-4.32.1.jar tinkuser.MainClass`
