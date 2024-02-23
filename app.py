#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
import cdk_nag
from aws_cdk import App, Environment, Aspects

from eks_nitro_wallet.eks_nitro_cluster_stack import EksNitroWalletStack
from eks_nitro_wallet.eth_key_management_app_stack import NitroWalletAppStack

prefix = os.getenv("CDK_PREFIX", "")

app = App()
EksNitroWalletStack(
    app,
    "{}EksNitroCluster".format(prefix),
    env=Environment(
        region=os.environ.get("CDK_DEPLOY_REGION"),
        account=os.environ.get("CDK_DEPLOY_ACCOUNT"),
    ),
)

NitroWalletAppStack(
    app,
    "{}EthKeyManagementApp".format(prefix),
    params={"log_level": os.environ.get("APP_LOG_LEVEL", "INFO")},
    env=Environment(
        region=os.environ.get("CDK_DEPLOY_REGION"),
        account=os.environ.get("CDK_DEPLOY_ACCOUNT"),
    ),
)

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks(verbose=False))
app.synth()
