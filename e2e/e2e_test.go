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
	operatorName       = "veth-ethtool"
	operatorImage      = "quay.io/akaris/veth-ethtool:latest"
	podRegex           = "red-|blue-"
	testDeploymentName = "red-deployment"
)

func TestRun(t *testing.T) {
	deploymentFeature := features.New("veth-ethtool").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Deploy operator.
			ethCfg := config.Config{
				EthernetConfigs: []config.EthernetConfig{
					{
						Namespace: cfg.Namespace(),
						Name:      podRegex,
						EthtoolSettings: map[string]bool{
							"tx-checksumming": false,
							"rx":              false,
						},
					},
				},
			}
			configMap := newConfigMap(cfg.Namespace(), operatorName, ethCfg)
			if err := cfg.Client().Resources().Create(ctx, configMap); err != nil {
				t.Fatal(err)
			}
			daemonSet := newDaemonset(cfg.Namespace(), operatorName, operatorImage, configMap.Name)
			if err := cfg.Client().Resources().Create(ctx, daemonSet); err != nil {
				t.Fatal(err)
			}

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
					if err := cfg.Client().Resources().Get(ctx, operatorName, cfg.Namespace(), &ds); err != nil {
						return err
					}
					if !isDaemonSetReady(&ds) {
						return fmt.Errorf("DaemonSet not ready yet")
					}
					return nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			// Give things 5 seconds to settle.
			time.Sleep(time.Second * 5)
			return context.WithValue(ctx, fmt.Sprintf("daemonset/%s", operatorName), &ds)
		}).
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployment := newDeployment(cfg.Namespace(), testDeploymentName, 1)
			if err := cfg.Client().Resources().Create(ctx, deployment); err != nil {
				t.Fatal(err)
			}

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
					if err := cfg.Client().Resources().Get(ctx, testDeploymentName, cfg.Namespace(), &dep); err != nil {
						return err
					}
					if !isDeploymentReady(&dep) {
						return fmt.Errorf("Deployment not ready yet")
					}
					return nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if &dep != nil {
				t.Logf("deployment found: %s", dep.Name)
			}
			// Give things 5 seconds to settle.
			time.Sleep(time.Second * 60)
			return context.WithValue(ctx, testDeploymentName, &dep)
		}).
		Assess("test deployment creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			dep := ctx.Value(testDeploymentName).(*appsv1.Deployment)
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

func newDaemonset(namespace, name, image, configMapName string) *appsv1.DaemonSet {
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
