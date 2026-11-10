#!/usr/bin/env bash
# Builds and tests everything in Docker, then signs the release on this machine with gpg and
# packs it into a Maven Central bundle. gpg-agent asks for the key's passphrase.
#
# The script uploads the bundle with the Portal user token for server "central" in
# ~/.m2/settings.xml. Without one it asks for a token, or you can leave it empty and upload the
# bundle by hand in the Portal (central.sonatype.com, Publish). Either way the deployment waits
# in the Portal for you to press Publish.
#
# Set SIGNING_KEY to sign with a key other than the default below.
set -euo pipefail
cd "$(dirname "$0")/.."

SIGNING_KEY=${SIGNING_KEY:-5F78B3CA429A65F262B0E3D27CD6F762D57F5184}

if [ -n "$(git status --porcelain)" ]; then
  echo "The working tree has uncommitted changes" >&2
  exit 1
fi
gpg --list-secret-keys "$SIGNING_KEY" >/dev/null

scripts/docker-build.sh

version=$(sed -n 's/^version=//p' target/maven-archiver/pom.properties)
name="monocypher-java-$version"
dir="net/lastninja/monocypher/monocypher-java/$version"
bundle="build/$name-bundle.zip"

rm -rf build/bundle "$bundle"
mkdir -p "build/bundle/$dir"
cp target/"$name".jar target/"$name"-sources.jar target/"$name"-javadoc.jar "build/bundle/$dir/"
cp pom.xml "build/bundle/$dir/$name.pom"

(
  cd "build/bundle/$dir"
  for f in *.jar *.pom; do
    gpg --local-user "$SIGNING_KEY" --armor --detach-sign "$f"
    gpg --verify "$f.asc" "$f"
  done
  for f in *.jar *.pom *.asc; do
    openssl dgst -md5 "$f" | awk '{print $NF}' >"$f.md5"
    shasum -a 1 "$f" | cut -d' ' -f1 >"$f.sha1"
  done
)
(cd build/bundle && zip -qr "../$name-bundle.zip" net)
echo "Bundle: $bundle"

# Prints the base64 of "username:password" for the server "central" in ~/.m2/settings.xml, or
# nothing if there is none.
settings_token() {
  python3 -I - "$HOME/.m2/settings.xml" <<'EOF'
import base64, os, sys
import xml.etree.ElementTree as ET
if os.path.exists(sys.argv[1]):
    for server in ET.parse(sys.argv[1]).getroot().iter("server"):
        user, password = server.findtext("username"), server.findtext("password")
        if server.findtext("id") == "central" and user and password:
            print(base64.b64encode(f"{user}:{password}".encode()).decode())
            break
EOF
}

auth=$(settings_token)
if [ -n "$auth" ]; then
  echo "Using the Portal token for server central in ~/.m2/settings.xml"
else
  read -r -p "Portal token username (leave empty to upload by hand): " token_user
  if [ -z "$token_user" ]; then
    echo "Upload $bundle at https://central.sonatype.com/publishing, then press Publish."
    exit 0
  fi
  read -r -s -p "Portal token password: " token_pass
  echo
  auth=$(printf '%s:%s' "$token_user" "$token_pass" | base64 | tr -d '\n')
fi
deployment=$(curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer $auth" \
  --form "bundle=@$bundle" \
  "https://central.sonatype.com/api/v1/publisher/upload?publishingType=USER_MANAGED&name=$name")
echo "Uploaded as deployment $deployment."
echo "Check validation and press Publish at https://central.sonatype.com/publishing/deployments"
