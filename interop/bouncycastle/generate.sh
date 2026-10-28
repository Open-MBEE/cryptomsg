#!/usr/bin/env bash
# Regenerates testdata/bouncycastle with Bouncy Castle (version pinned in
# pom.xml), or verifies cryptomsg output with it:
#
#   interop/bouncycastle/generate.sh                 # write fixtures
#   interop/bouncycastle/generate.sh verify <dir>    # verify files written by
#                                                    # `go test -run TestWriteBouncyCastleInput -write-bc-input=<dir>`
#
# Needs a JDK (17+) and Maven; CI never runs this — the fixtures are committed.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mvn -q -f "$here/pom.xml" dependency:copy-dependencies -DoutputDirectory="$here/target/lib"
cp="$here/target/lib/*"
mkdir -p "$here/target/classes"
javac -d "$here/target/classes" -cp "$cp" "$here"/src/*.java
if [ "${1:-}" = "verify" ]; then
  java -cp "$here/target/classes:$cp" Fixtures verify "$2"
else
  java -cp "$here/target/classes:$cp" Fixtures generate "$root/testdata/bouncycastle"
fi
