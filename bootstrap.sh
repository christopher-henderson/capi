# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#!/usr/bin/env bash

set -e

mkdir nss
cd nss

which gyp
if [ $? -ne 0 ]; then
	git clone https://chromium.googlesource.com/external/gyp
    cd gyp
    ./setup.py
fi

which ninja
if [ $? -ne 0 ]; then
	# Sorry, don't feel like cross platform right now
	brew install ninja
fi

git clone https://github.com/nss-dev/nss.git

hg clone https://hg.mozilla.org/projects/nss
hg clone https://hg.mozilla.org/projects/nspr

cd nss
./build.sh -v
if [ $? -ne 0 ]; then
	echo "build failed"
	exit 1
fi
