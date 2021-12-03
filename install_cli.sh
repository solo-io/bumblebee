#!/bin/sh

set -eu

if [ -x "$(command -v python3)" ]; then
  alias any_python='python3'
elif [ -x "$(command -v python)" ]; then
  alias any_python='python'    
elif [ -x "$(command -v python2)" ]; then
  alias any_python='python2'    
else
  echo Python 2 or 3 is required to install bee
  exit 1
fi

if [ -z "${EBPF_VERSION:-}" ]; then
  EBPF_VERSIONS=$(curl -sH"Accept: application/vnd.github.v3+json" https://api.github.com/repos/solo-io/ebpf/releases | any_python -c "import sys; from distutils.version import StrictVersion, LooseVersion; from json import loads as l; releases = l(sys.stdin.read()); releases = [release['tag_name'] for release in releases];  filtered_releases = list(filter(lambda release_string: len(release_string) > 0 and StrictVersion.version_re.match(release_string[1:]) != None, releases)); filtered_releases.sort(key=LooseVersion, reverse=True); print('\n'.join(filtered_releases))")
else
  EBPF_VERSIONS="${EBPF_VERSION}"
fi

if [ "$(uname -s)" = "Linux" ]; then
  OS=linux
else
  echo Only linux is currently supported
  exit 1
fi

for ebpf_version in $EBPF_VERSIONS; do

tmp=$(mktemp -d /tmp/ebpf.XXXXXX)
filename="bee-${OS}-amd64"
url="https://github.com/solo-io/bumblebee/releases/download/${ebpf_version}/${filename}"

if curl -f ${url} >/dev/null 2>&1; then
  echo "Attempting to download bee version ${ebpf_version}"
else
  continue
fi

(
  cd "$tmp"

  echo "Downloading ${filename}..."

  SHA=$(curl -sL "${url}.sha256" | cut -d' ' -f1)
  curl -sLO "${url}"
  echo "Download complete!, validating checksum..."
  checksum=$(openssl dgst -sha256 "${filename}" | awk '{ print $2 }')
  if [ "$checksum" != "$SHA" ]; then
    echo "Checksum validation failed." >&2
    exit 1
  fi
  echo "Checksum valid."
)

(
  cd "$HOME"
  mkdir -p ".ebpf/bin"
  mv "${tmp}/${filename}" ".ebpf/bin/bee"
  chmod +x ".ebpf/bin/bee"
)

rm -r "$tmp"

echo "bee was successfully installed 🎉"
echo ""
echo "Add the eBPF CLI to your path with:"
echo "  export PATH=\$HOME/.ebpf/bin:\$PATH"
echo ""
echo "Now run:"
echo "  bee init     # Initialize simple eBPF program to run with bee"
echo "Please see visit the Gloo Mesh website for more info:  https://www.solo.io/products/ebpf/"
exit 0
done

echo "No versions of bee found."
exit 1