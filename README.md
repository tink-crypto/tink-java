# Tink Java

<!-- GCP Ubuntu --->

[tink_java_bazel_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-java-bazel-gcp-ubuntu.svg
[tink_java_maven_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-java-maven-gcp-ubuntu.svg

<!-- MacOS --->

[tink_java_bazel_badge_macos]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-java-bazel-macos-external.svg

**Test**      | **GCP Ubuntu**                                            | **MacOS**
------------- | --------------------------------------------------------- | ------------------------------------------------
Bazel         | [![Bazel_GcpUbuntu][tink_java_bazel_badge_gcp_ubuntu]](#) | [![Bazel_MacOs][tink_java_bazel_badge_macos]](#)
Maven         | [![Maven_GcpUbuntu][tink_java_maven_badge_gcp_ubuntu]](#) | N/A


Using crypto in your application [shouldn't have to][devs_are_users_too_slides]
feel like juggling chainsaws in the dark. Tink is a crypto library written by a
group of cryptographers and security engineers at Google. It was born out of our
extensive experience working with Google's product teams,
[fixing weaknesses in implementations](https://github.com/google/wycheproof),
and providing simple APIs that can be used safely without needing a crypto
background.

Tink provides secure APIs that are easy to use correctly and hard(er) to misuse.
It reduces common crypto pitfalls with user-centered design, careful
implementation and code reviews, and extensive testing. At Google, Tink is one
of the standard crypto libraries, and has been deployed in hundreds of products
and systems.

To get a quick overview of Tink's design please take a look at
[Tink's goals](https://developers.google.com/tink/design/goals_of_tink).

The official documentation is available at https://developers.google.com/tink.

[devs_are_users_too_slides]: https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf

## Contact and mailing list

If you want to contribute, please read [CONTRIBUTING](docs/CONTRIBUTING.md) and
send us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major product
updates, you may want to subscribe to our
[mailing list](https://groups.google.com/forum/#!forum/tink-users).

## Maintainers

Tink is maintained by (A-Z):

-   Moreno Ambrosin
-   Taymon Beal
-   William Conner
-   Thomas Holenstein
-   Stefan Kölbl
-   Charles Lee
-   Cindy Lin
-   Fernando Lobato Meeser
-   Ioana Nedelcu
-   Sophie Schmieg
-   Elizaveta Tretiakova
-   Jürg Wullschleger

Alumni:

-   Haris Andrianakis
-   Daniel Bleichenbacher
-   Tanuj Dhir
-   Thai Duong
-   Atul Luykx
-   Rafael Misoczki
-   Quan Nguyen
-   Bartosz Przydatek
-   Enzo Puig
-   Laurent Simon
-   Veronika Slívová
-   Paula Vidas
