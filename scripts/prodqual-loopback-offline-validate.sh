#!/bin/sh
# Offline validation for macos_prodqual_loopback. No apply. No install.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

INVENTORY="${REPO_ROOT}/inventory/prodqual_loopback_fixture/hosts.ini"
VALIDATE="${REPO_ROOT}/playbooks/macos-prodqual-loopback-validate.yml"
BACKUP="${REPO_ROOT}/playbooks/macos-prodqual-loopback-backup.yml"
ROLLBACK="${REPO_ROOT}/playbooks/macos-prodqual-loopback-rollback.yml"
APPLY="${REPO_ROOT}/playbooks/macos-prodqual-loopback.yml"
TEST_CFG="${REPO_ROOT}/tests/prodqual_loopback/ansible.cfg"

export ANSIBLE_CONFIG="${TEST_CFG}"
export ANSIBLE_RETRY_FILES_ENABLED=false

echo "T1 ansible-playbook --syntax-check validate"
ansible-playbook -i "${INVENTORY}" "${VALIDATE}" --syntax-check
echo "T1 exit=$?"

echo "T2 ansible-playbook --syntax-check backup"
ansible-playbook -i "${INVENTORY}" "${BACKUP}" --syntax-check
echo "T2 exit=$?"

echo "T3 ansible-playbook --syntax-check rollback"
ansible-playbook -i "${INVENTORY}" "${ROLLBACK}" --syntax-check
echo "T3 exit=$?"

echo "T4 ansible-playbook --syntax-check apply (syntax only)"
ansible-playbook -i "${INVENTORY}" "${APPLY}" --syntax-check
echo "T4 exit=$?"

echo "T5 ansible-playbook --check validate"
ansible-playbook -i "${INVENTORY}" "${VALIDATE}" --check
echo "T5 exit=$?"

echo "T6 ansible-playbook --check validate second run"
ansible-playbook -i "${INVENTORY}" "${VALIDATE}" --check
echo "T6 exit=$?"

echo "T7 python offline tests"
python3 "${REPO_ROOT}/tests/prodqual_loopback/test_offline.py"
echo "T7 exit=$?"
