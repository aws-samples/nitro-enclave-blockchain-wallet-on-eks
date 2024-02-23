import aws_cdk as core
import aws_cdk.assertions as assertions

from eks_nitro_wallet.eks_nitro_cluster_stack import EksNitroWalletStack

# example tests. To run these tests, uncomment this file along with the example
# resource in eks_nitro_wallet/eks_nitro_cluster_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = EksNitroWalletStack(app, "eks-nitro-wallet")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
