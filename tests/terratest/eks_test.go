package test

import (
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestEKSCluster(t *testing.T) {
	t.Parallel()

	// Terraform options for the EKS module
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		// Path to the Terraform directory
		TerraformDir: "../../kubernetes",

		// Variables to pass to our Terraform code
		Vars: map[string]interface{}{
			"region": "us-east-1",
		},
	})

	// At the end of the test, destroy the infrastructure
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the infrastructure using Terraform
	terraform.InitAndApply(t, terraformOptions)

	// Get the output from Terraform
	clusterName := terraform.Output(t, terraformOptions, "eks_cluster_name")

	// Configure kubectl to use the EKS cluster
	kubectl := k8s.NewKubectlOptions("", "", "postgres-security")

	// Wait for the EKS cluster to be ready
	aws.WaitForEksCluster(t, "us-east-1", clusterName, 10, 30*time.Second)

	// Get the Kubernetes namespace
	namespace, err := k8s.GetNamespaceE(t, kubectl, "postgres-security")
	assert.NoError(t, err)
	assert.Equal(t, "postgres-security", namespace.Name)

	// Verify the StatefulSet creation
	statefulset, err := k8s.GetStatefulSetE(t, kubectl, "postgres-security")
	assert.NoError(t, err)
	assert.Equal(t, int32(1), *statefulset.Spec.Replicas)

	// Wait for the pod to be ready
	k8s.WaitUntilNumPodsCreated(t, kubectl, kubectl.Namespace, k8s.MetadataFilterWithLabels(map[string]string{"app": "postgres-security"}), 1, 30, 10*time.Second)
	pods := k8s.ListPods(t, kubectl, kubectl.Namespace, k8s.MetadataFilterWithLabels(map[string]string{"app": "postgres-security"}))
	assert.Equal(t, 1, len(pods))

	// Wait for the pod to be ready
	k8s.WaitUntilPodAvailable(t, kubectl, pods[0].Name, 10, 5*time.Second)

	// Verify network policy exists
	networkPolicy, err := k8s.GetNetworkPolicyE(t, kubectl, "postgres-security-network-policy")
	assert.NoError(t, err)
	assert.NotNil(t, networkPolicy)

	// Verify service exists
	service, err := k8s.GetServiceE(t, kubectl, "postgres-security")
	assert.NoError(t, err)
	assert.Equal(t, int32(5432), service.Spec.Ports[0].Port)
}
