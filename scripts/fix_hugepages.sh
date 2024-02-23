#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'

nodes=$(kubectl get nodes -o json | jq -r '.items[].metadata.name')
instance_ids=""
for node in ${nodes}; do
  old_hugepages=$(kubectl describe node "${node}" | grep hugepages-1Gi: | head -n 1 | tail -c 5)
  echo -e "${node}: ${RED}${old_hugepages}${NC}"
  instance_ids+=$(aws ec2 describe-instances --filter Name=private-dns-name,Values="${node}" | jq -r '.Reservations[0].Instances[0].InstanceId')" "
done

status_command_id_hot=$(aws ssm send-command --document-name "AWS-RunShellScript" --instance-ids "${instance_ids}" --parameters 'commands=["sudo systemctl restart nitro-enclaves-allocator.service && sleep 5 && sudo systemctl restart kubelet"]' | jq -r '.Command.CommandId')

sleep 10

instance_ids_nl=$(echo "${instance_ids}" | tr "\n " " ")
for instance_id in ${instance_ids_nl}; do
  status=$(aws ssm list-command-invocations --instance-id "${instance_id}" --command-id "${status_command_id_hot}" --details | jq -r '.CommandInvocations[].CommandPlugins[].StatusDetails')
  echo "${instance_id}: ${status}"
done

# todo wrap in function
for node in ${nodes}; do
  new_hugepages=$(kubectl describe node "${node}" | grep hugepages-1Gi: | head -n 1 | tail -c 5)
  echo -e "${node}: ${GREEN}${new_hugepages}${NC}"
done