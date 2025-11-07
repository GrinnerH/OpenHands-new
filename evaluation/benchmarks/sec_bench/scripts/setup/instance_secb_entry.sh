#!/bin/bash

source ~/.bashrc
SECB_UTIL_DIR=/secb_util

# FIXME: Cannot read SWE_INSTANCE_ID from the environment variable
# SWE_INSTANCE_ID=django__django-11099
if [ -z "$SECB_INSTANCE_ID" ]; then
    echo "Error: SECB_INSTANCE_ID is not set." >&2
    exit 1
fi

if [ -z "$SECB_WORK_DIR" ]; then
    echo "Error: SECB_WORK_DIR is not set." >&2
    exit 1
fi

# Read the secb-instance.json file and extract the required item based on instance_id
item=$(jq --arg INSTANCE_ID "$SECB_INSTANCE_ID" '.[] | select(.instance_id == $INSTANCE_ID)' $SECB_UTIL_DIR/eval_data/instances/secb-instance.json)

if [[ -z "$item" ]]; then
  echo "No item found for the provided instance ID."
  exit 1
fi

# WORKSPACE_NAME=$(echo "$item" | jq -r '(.repo | tostring) | gsub("/"; "__")')

# echo "WORKSPACE_NAME: $WORKSPACE_NAME"

# Clear the workspace
# if [ -d /workspace ]; then
#     rm -rf /workspace/*
# else
#     mkdir /workspace
# fi
# # Copy repo to workspace
# if [ -d /workspace/$WORKSPACE_NAME ]; then
#     rm -rf /workspace/$WORKSPACE_NAME
# fi
# mkdir -p /workspace
# cp -r $SECB_WORK_DIR /workspace/$WORKSPACE_NAME
