/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/andreaskaris/veth-ethtool/pkg/config"
	"k8s.io/apimachinery/pkg/api/errors"
)

const (
	operatorName        = "veth-ethtool"
	operatorImage       = "quay.io/akaris/veth-ethtool:latest"
	podRegex            = "red-|blue-"
	testDeployment0Name = "red-deployment"
	testDeployment1Name = "blue-deployment"
)

func TestRun(t *testing.T) {
	deploymentFeature := features.New("veth-ethtool").
		// Setup a deployment before the operator is deployed.
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			testDeploymentName := testDeployment0Name
			deployment := newDeployment(cfg.Namespace(), testDeploymentName, 1)
			if err := cfg.Client().Resources().Create(ctx, deployment); err != nil {
				t.Fatal(err)
			}
			dep, err := waitForDeployment(ctx, cfg, cfg.Namespace(), testDeploymentName)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("deployment found: %s/%s", dep.Namespace, dep.Name)

			// Give things 5 seconds to settle.
			time.Sleep(time.Second * 5)
			return context.WithValue(ctx, testDeploymentName, dep)
		}).
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Deploy operator.
			ethCfg := config.Config{
				EthernetConfigs: []config.EthernetConfig{
					{
						Namespace: cfg.Namespace(),
						Name:      podRegex,
						EthtoolSettings: map[string]bool{
							"tx-checksumming": false,
							"rx-checksumming": false,
						},
					},
				},
			}
			configMap := newConfigMap(cfg.Namespace(), operatorName, ethCfg)
			if err := cfg.Client().Resources().Create(ctx, configMap); err != nil {
				t.Fatal(err)
			}
			daemonSet := newOperatorDaemonset(cfg.Namespace(), operatorName, operatorImage, configMap.Name)
			if err := cfg.Client().Resources().Create(ctx, daemonSet); err != nil {
				t.Fatal(err)
			}
			ds, err := waitForDaemonSet(ctx, cfg, cfg.Namespace(), operatorName)
			if err != nil {
				t.Fatal(err)
			}

			// Give things 5 seconds to settle.
			time.Sleep(time.Second * 5)
			return context.WithValue(ctx, fmt.Sprintf("daemonset/%s", operatorName), ds)
		}).
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			testDeploymentName := testDeployment1Name
			deployment := newDeployment(cfg.Namespace(), testDeploymentName, 1)
			if err := cfg.Client().Resources().Create(ctx, deployment); err != nil {
				t.Fatal(err)
			}
			dep, err := waitForDeployment(ctx, cfg, cfg.Namespace(), testDeploymentName)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("deployment found: %s/%s", dep.Namespace, dep.Name)

			// Give things 5 seconds to settle.
			time.Sleep(time.Second * 5)
			return context.WithValue(ctx, testDeploymentName, dep)
		}).
		Assess("test ethernet status creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			listOption := func(lo *metav1.ListOptions) {
				lo.LabelSelector = fmt.Sprintf("app=%s", operatorName)
			}
			pods := &corev1.PodList{}
			err := cfg.Client().Resources(cfg.Namespace()).List(context.TODO(), pods, listOption)
			if err != nil || pods.Items == nil {
				t.Error("error while getting pods", err)
			}
			script := `for intf in $(ip a | awk -F '@| ' '/veth/ {print $2}'); do echo -n "$intf "; ethtool -k $intf | grep -E 'tx-checksumming'; echo -n "$intf "; ethtool -k $intf | grep -E 'rx-checksumming'; done`
			for _, p := range pods.Items {
				var stdout, stderr bytes.Buffer
				command := []string{"/bin/bash", "-c", script}
				if err := cfg.Client().Resources().ExecInPod(ctx, p.Namespace, p.Name, operatorName, command, &stdout, &stderr); err != nil {
					t.Log(stderr.String())
					t.Fatal(err)
				}
				t.Logf("pod %q, stdout: '%s', stderr: '%s'", p.Name, stdout.String(), stderr.String())
			}
			time.Sleep(60 * time.Second)
			// TODO: automate this.
			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			dep := ctx.Value(testDeployment0Name).(*appsv1.Deployment)
			if err := cfg.Client().Resources().Delete(ctx, dep); err != nil {
				t.Fatal(err)
			}
			dep = ctx.Value(testDeployment1Name).(*appsv1.Deployment)
			if err := cfg.Client().Resources().Delete(ctx, dep); err != nil {
				t.Fatal(err)
			}
			ds := ctx.Value(fmt.Sprintf("daemonset/%s", operatorName)).(*appsv1.DaemonSet)
			if err := cfg.Client().Resources().Delete(ctx, ds); err != nil {
				t.Fatal(err)
			}
			return ctx
		}).Feature()

	testenv.Test(t, deploymentFeature)
}

func newDeployment(namespace string, name string, replicaCount int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app": "test-app"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test-app"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test-app"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "nginx"}}},
			},
		},
	}
}

// TODO: replace with https://github.com/kubernetes-sigs/e2e-framework/tree/main/examples/wait_for_resources.
func waitForDeployment(ctx context.Context, cfg *envconf.Config, namespace, name string) (*appsv1.Deployment, error) {
	var dep appsv1.Deployment
	err := retry.OnError(
		wait.Backoff{Duration: 5 * time.Second, Factor: 1, Steps: 12, Cap: 120 * time.Second},
		func(err error) bool {
			if errors.IsNotFound(err) {
				klog.Infof("Could not find Deployment")
				return true
			}
			if strings.Contains(err.Error(), "Deployment not ready yet") {
				klog.Infof("Deployment is not ready, yet")
				return true
			}
			return false
		},
		func() error {
			if err := cfg.Client().Resources().Get(ctx, name, namespace, &dep); err != nil {
				return err
			}
			if !isDeploymentReady(&dep) {
				return fmt.Errorf("Deployment not ready yet")
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return &dep, nil
}

func newOperatorDaemonset(namespace, name, image, configMapName string) *appsv1.DaemonSet {
	labels := map[string]string{"app": name}
	mountPropagation := corev1.MountPropagationHostToContainer
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name:            name,
							Image:           image,
							ImagePullPolicy: corev1.PullNever,
							Command: []string{
								"/usr/local/bin/veth-ethtool",
								"-v=2",
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "host", MountPath: "/host"},
								{Name: "netns", MountPath: "/run/netns", MountPropagation: &mountPropagation},
								{Name: "config", MountPath: "/etc/veth-ethtool"},
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
									},
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "host",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{Path: "/"},
							},
						},
						{
							Name: "netns",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{Path: "/run/netns"},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
									DefaultMode:          pointer.Int32(0420),
								},
							},
						},
					},
				},
			},
		},
	}
}

// TODO: replace with https://github.com/kubernetes-sigs/e2e-framework/tree/main/examples/wait_for_resources.
func waitForDaemonSet(ctx context.Context, cfg *envconf.Config, namespace, name string) (*appsv1.DaemonSet, error) {
	var ds appsv1.DaemonSet
	err := retry.OnError(
		wait.Backoff{Duration: 5 * time.Second, Factor: 1, Steps: 12, Cap: 120 * time.Second},
		func(err error) bool {
			if errors.IsNotFound(err) {
				klog.Infof("Could not find DaemonSet")
				return true
			}
			if strings.Contains(err.Error(), "DaemonSet not ready yet") {
				klog.Infof("DaemonSet is not ready, yet")
				return true
			}
			return false
		},
		func() error {
			if err := cfg.Client().Resources().Get(ctx, name, namespace, &ds); err != nil {
				return err
			}
			if !isDaemonSetReady(&ds) {
				return fmt.Errorf("DaemonSet not ready yet")
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return &ds, nil
}

func newConfigMap(namespace, name string, cfg config.Config) *corev1.ConfigMap {
	labels := map[string]string{"app": name}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Data: map[string]string{
			"config.json": cfg.String(),
		},
	}
}

func isDaemonSetReady(ds *appsv1.DaemonSet) bool {
	n := ds.Status.DesiredNumberScheduled
	return n == ds.Status.CurrentNumberScheduled && n == ds.Status.NumberReady && n == ds.Status.NumberAvailable
}

func isDeploymentReady(dep *appsv1.Deployment) bool {
	n := dep.Status.Replicas
	return n == dep.Status.AvailableReplicas && n == dep.Status.ReadyReplicas && n == dep.Status.UpdatedReplicas
}
