#!/bin/sh

CURRENT_BUILD=$(git ls-remote --tags origin 'v2.*' | tail -1 | cut -f3 -d.)
if [ -z "$CURRENT_BUILD" ]; then
	RELEASE_BUILD=0
else
	RELEASE_BUILD=$((CURRENT_BUILD+1))
fi
RELEASE_TAG="v2.0.$RELEASE_BUILD"
echo "#define VERSION_STR \""$RELEASE_TAG"\"" > ./src/version.h
echo "RELEASE_TAG="$RELEASE_TAG"" >> "$GITHUB_ENV"
