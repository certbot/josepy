#!/bin/bash -xe
# Release dev packages to PyPI

PrintUsageAndExit() {
    echo Usage:
    echo "$0 --changelog-ok <release version> <next version>"
    exit 1
}

if [ "`dirname $0`" != "tools" ] ; then
    echo Please run this script from the repo root
    exit 1
fi

if ! poetry export --help 2>&1 | grep -q constraints.txt ; then
    # turn off set -x for saner output
    set +x
    echo 'Please install poetry with poetry-plugin-export>=1.1.0'
    echo 'before running this script.'
    exit 1
fi

if [ "$1" != "--changelog-ok" ]; then
    # turn off set -x for saner output
    set +x
    echo "Make sure the changelog includes the exact text you want for the"
    echo "release and run the script again with --changelog-ok."
    echo
    PrintUsageAndExit
fi

CheckVersion() {
    # Args: <description of version type> <version number>
    if ! echo "$2" | grep -q -e '[0-9]\+.[0-9]\+.[0-9]\+' ; then
        echo "$1 doesn't look like 1.2.3"
        exit 1
    fi
}

version="$2"
CheckVersion Version "$version"
echo Releasing production version "$version"...
nextversion="$3"
CheckVersion "Next version" "$nextversion"
RELEASE_BRANCH="candidate-$version"

# If RELEASE_GPG_KEY isn't set, determine the key to use.
if [ "$RELEASE_GPG_KEY" = "" ]; then
    TRUSTED_KEYS="
        BF6BCFC89E90747B9A680FD7B6029E8500F7DB16
        86379B4F0AF371B50CD9E5FF3402831161D1D280
        20F201346BF8F3F455A73F9A780CC99432A28621
        F2871B4152AE13C49519111F447BF683AA3B26C3
    "
    for key in $TRUSTED_KEYS; do
        if gpg --with-colons --card-status | grep -q "$key"; then
            RELEASE_GPG_KEY="$key"
            break
        fi
    done
    if [ "$RELEASE_GPG_KEY" = "" ]; then
        echo A trusted PGP key was not found on your PGP card.
        exit 1
    fi
fi

# Needed to fix problems with git signatures and pinentry
export GPG_TTY=$(tty)

# port for a local Python Package Index (used in testing)
PORT=${PORT:-1234}

tag="v$version"
mv "dist.$version" "dist.$version.$(date +%s).bak" || true
git tag --delete "$tag" || true

root_without_jose="$version.$$"
root="./releases/jose.$root_without_jose"

echo "Cloning into fresh copy at $root"  # clean repo = no artifacts
git clone . $root
git rev-parse HEAD
cd $root
if [ "$RELEASE_BRANCH" != "candidate-$version" ] ; then
    git branch -f "$RELEASE_BRANCH"
fi
git checkout "$RELEASE_BRANCH"

SetVersion() {
    ver="$1"
    short_ver=$(echo "$ver" | cut -d. -f1,2)
    sed -i "s/^release.*/release = \"$ver\"/" docs/conf.py
    sed -i "s/^version.*/version = \"$short_ver\"/" docs/conf.py
    poetry version "$ver"

    # interactive user input
    git add -p .

}

SetVersion "$version"

echo "Preparing sdists and wheels"
poetry build

echo "Signing josepy"
for x in dist/*.tar.gz dist/*.whl
do
  gpg -u "$RELEASE_GPG_KEY" --detach-sign --armor --sign --digest-algo sha256 $x
done

mkdir "dist.$version"
mv dist "dist.$version/josepy"
poetry export -f constraints.txt --with dev --without-hashes > constraints.txt

echo "Testing packages"
cd "dist.$version"
# start local PyPI
python3 -m http.server "$PORT" &
# cd .. is NOT done on purpose: we make sure that all subpackages are
# installed from local PyPI rather than current directory (repo root)
python3 -m venv ../venv
. ../venv/bin/activate
pip install -U setuptools
pip install -U pip
# Now, use our local PyPI. Disable cache so we get the correct KGS even if we
# (or our dependencies) have conditional dependencies implemented with if
# statements in setup.py and we have cached wheels lying around that would
# cause those ifs to not be evaluated.
pip install \
  --no-cache-dir \
  --extra-index-url http://localhost:$PORT \
  --constraint ../constraints.txt \
  josepy pytest
# stop local PyPI
kill $!
cd ~-

cd ..
# freeze before installing anything else, so that we know end-user KGS
# make sure "twine upload" doesn't catch "kgs"
if [ -d kgs ] ; then
    echo Deleting old kgs...
    rm -rf kgs
fi
mkdir kgs
kgs="kgs/$version"
pip freeze | tee $kgs
cd ~-
echo testing josepy
pytest
deactivate

git commit --gpg-sign="$RELEASE_GPG_KEY" -m "Release $version"
git tag --local-user "$RELEASE_GPG_KEY" --sign --message "Release $version" "$tag"

echo Now run twine upload "$root/dist.$version/*/*"

if [ "$RELEASE_BRANCH" = candidate-"$version" ] ; then
    SetVersion "$nextversion".dev0
    git commit -m "Bump version to $nextversion"
fi
