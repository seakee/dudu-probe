#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="${SCRIPT_DIR}/install.sh"

bash -n "${INSTALL_SH}"

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT}"' EXIT

FAKE_BIN="${TEST_ROOT}/fake-bin"
WORK_TMP="${TEST_ROOT}/work-tmp"
ARCHIVE_SRC="${TEST_ROOT}/archive-src/dudu-probe_1.0.0_darwin_amd64"
ARCHIVE_FILE="${TEST_ROOT}/dudu-probe_1.0.0_darwin_amd64.tar.gz"
STATE_FILE="${TEST_ROOT}/launchctl.log"

mkdir -p "${FAKE_BIN}" "${WORK_TMP}" "${ARCHIVE_SRC}"

cat >"${ARCHIVE_SRC}/dudu-probe" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-version" ]]; then
  echo "dudu-probe v1.0.0-test"
  exit 0
fi
exit 0
EOF
chmod 0755 "${ARCHIVE_SRC}/dudu-probe"
tar -C "${TEST_ROOT}/archive-src" -czf "${ARCHIVE_FILE}" "dudu-probe_1.0.0_darwin_amd64"

cat >"${FAKE_BIN}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) echo "Darwin" ;;
  -m) echo "x86_64" ;;
  *) echo "Darwin" ;;
esac
EOF

cat >"${FAKE_BIN}/id" <<'EOF'
#!/usr/bin/env bash
echo "0"
EOF

cat >"${FAKE_BIN}/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o)
      out="\$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "${ARCHIVE_FILE}" "\${out}"
EOF

cat >"${FAKE_BIN}/launchctl" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"${STATE_FILE}"
if [[ "\${1:-}" == "list" ]]; then
  echo "12345 0 com.seakee.dudu-probe"
fi
EOF

cat >"${FAKE_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "unexpected systemctl call on Darwin" >&2
exit 99
EOF

cat >"${FAKE_BIN}/rc-service" <<'EOF'
#!/usr/bin/env bash
echo "unexpected rc-service call on Darwin" >&2
exit 99
EOF

chmod 0755 "${FAKE_BIN}/uname" "${FAKE_BIN}/id" "${FAKE_BIN}/curl" "${FAKE_BIN}/launchctl" "${FAKE_BIN}/systemctl" "${FAKE_BIN}/rc-service"

PATCHED_INSTALL="${TEST_ROOT}/install-under-test.sh"
sed \
  -e "s|^INSTALL_BIN=.*|INSTALL_BIN=\"${TEST_ROOT}/usr/local/bin/dudu-probe\"|" \
  -e "s|^CONFIG_DIR=.*|CONFIG_DIR=\"${TEST_ROOT}/etc/dudu-probe\"|" \
  -e "s|^OPENRC_INIT=.*|OPENRC_INIT=\"${TEST_ROOT}/nonexistent-init-dir/dudu-probe\"|" \
  -e "s|^LAUNCHD_PLIST=.*|LAUNCHD_PLIST=\"${TEST_ROOT}/Library/LaunchDaemons/com.seakee.dudu-probe.plist\"|" \
  -e "s|^LAUNCHD_LOG=.*|LAUNCHD_LOG=\"${TEST_ROOT}/var/log/dudu-probe.log\"|" \
  -e "s|^LAUNCHD_ERR=.*|LAUNCHD_ERR=\"${TEST_ROOT}/var/log/dudu-probe.err\"|" \
  -e 's|\${EUID:-\$(id -u)}|\$(id -u)|' \
  "${INSTALL_SH}" >"${PATCHED_INSTALL}"
chmod 0755 "${PATCHED_INSTALL}"

mkdir -p "${TEST_ROOT}/var/log"
touch "${TEST_ROOT}/var/log/dudu-probe.log" "${TEST_ROOT}/var/log/dudu-probe.err"

run_installer() {
  PATH="${FAKE_BIN}:${PATH}" TMPDIR="${WORK_TMP}" \
    bash "${PATCHED_INSTALL}" "$@"
}

run_installer install \
  --version "v1.0.0" \
  --server "http://127.0.0.1:8000" \
  --key "probe_test" \
  --secret "sec_test" \
  --interval 15

test -x "${TEST_ROOT}/usr/local/bin/dudu-probe"
test -f "${TEST_ROOT}/etc/dudu-probe/config.json"
test -f "${TEST_ROOT}/Library/LaunchDaemons/com.seakee.dudu-probe.plist"
test ! -e "${TEST_ROOT}/nonexistent-init-dir/dudu-probe"
test -z "$(find "${WORK_TMP}" -mindepth 1 -maxdepth 1 -print -quit)"

run_installer status | grep -q "com.seakee.dudu-probe"
run_installer restart
run_installer upgrade --version "v1.0.0"
grep -q '"report_interval_sec": 15' "${TEST_ROOT}/etc/dudu-probe/config.json"
test -z "$(find "${WORK_TMP}" -mindepth 1 -maxdepth 1 -print -quit)"

run_installer uninstall
for removed in \
  "${TEST_ROOT}/usr/local/bin/dudu-probe" \
  "${TEST_ROOT}/etc/dudu-probe" \
  "${TEST_ROOT}/Library/LaunchDaemons/com.seakee.dudu-probe.plist" \
  "${TEST_ROOT}/var/log/dudu-probe.log" \
  "${TEST_ROOT}/var/log/dudu-probe.err"; do
  if [[ -e "${removed}" ]]; then
    echo "expected uninstall to remove ${removed}" >&2
    exit 1
  fi
done
