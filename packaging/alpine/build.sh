#!/bin/sh
set -eu

die() {
	echo "netcontrol APK build: $*" >&2
	exit 1
}

[ "$(id -u)" -ne 0 ] || die "run as an unprivileged Alpine abuild user"
for tool in abuild abuild-keygen apk git go sha256sum; do
	command -v "$tool" >/dev/null || die "missing dependency: $tool"
done

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
[ -z "$(git status --porcelain)" ] || die "build requires a clean, committed checkout"
case "$(apk --print-arch)" in
	x86_64|aarch64) ;;
	*) die "supported architectures: x86_64, aarch64" ;;
esac

commit=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$commit")
export SOURCE_DATE_EPOCH
export NETCONTROL_PKGVER="0_git$SOURCE_DATE_EPOCH"
out=${OUTDIR:-"$repo/dist"}
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)
[ -z "$(ls -A "$out")" ] || die "output directory must be empty: $out"

work=$(mktemp -d "${TMPDIR:-/tmp}/netcontrol-apk.XXXXXX")
trap 'rm -rf -- "${work:?}"' EXIT
trap 'exit 1' HUP INT TERM
export ABUILD_USERDIR="$work/keys"
export ABUILD_USERCONF="$ABUILD_USERDIR/abuild.conf"
mkdir -p "$work/aports/netcontrol"
cp packaging/alpine/APKBUILD packaging/alpine/netcontrold.initd \
	packaging/alpine/netcontrold.confd "$work/aports/netcontrol/"
git archive --format=tar --prefix="netcontrol-$NETCONTROL_PKGVER/" \
	-o "$work/source.tar" "$commit"
gzip -c "$work/source.tar" >"$work/aports/netcontrol/netcontrol-$NETCONTROL_PKGVER.tar.gz"
abuild-keygen -a -n
cd "$work/aports/netcontrol"
abuild checksum
abuild -r -P "$work/packages"
find "$work/packages" -type f -name '*.apk' -exec cp '{}' "$out/" \;
set -- "$out"/*.apk
[ -f "$1" ] || die "abuild produced no APK"
cp "$ABUILD_USERDIR"/*.rsa.pub "$out/"
printf '{"commit":"%s","source_date_epoch":%s,"package_version":"%s-r0","architecture":"%s","alpine":"%s","go":"%s"}\n' \
	"$commit" "$SOURCE_DATE_EPOCH" "$NETCONTROL_PKGVER" "$(apk --print-arch)" \
	"$(cat /etc/alpine-release)" "$(go version)" >"$out/BUILDINFO.json"
cd "$out"
sha256sum ./*.apk ./*.rsa.pub ./BUILDINFO.json >SHA256SUMS
echo "Development APK artifacts: $out"
