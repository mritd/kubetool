/*
 * Copyright 2018 mritd <mritd1234@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobuffalo/packr"
	"github.com/spf13/viper"

	"github.com/mritd/kubetool/utils"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	defaultKubeConfigDir     = "kubetool/kubeconfig"
	defaultBootstrapConfig   = defaultKubeConfigDir + "/bootstrap.kubeconfig"
	defaultKubeproxyConfig   = defaultKubeConfigDir + "/kube-proxy.kubeconfig"
	defaultAuditPolicyConfig = "kubetool/audit-policy/audit-policy.yaml"
	defaultCluster           = "kubernetes"
	defaultContext           = "default"
	kubeproxyUser            = "kube-proxy"
	bootstrapUserPrefix      = "system:bootstrap"
)

func CreateBootstrapToken() (id, secret string) {
	// refs https://github.com/kubernetes/community/blob/master/contributors/design-proposals/cluster-lifecycle/bootstrap-discovery.md#new-bootstrap-token-structure
	return utils.NewLowerNumberLen(6), utils.NewLowerNumberLen(16)
}

func CreateBootstrapConfig(apiServer, bootstrapToken, configPath, k8sCAPath string, k8sCA []byte) error {

	sp := strings.Split(bootstrapToken, ".")
	if len(sp) != 2 {
		return errors.New("bootstrap token format error")
	}
	if strings.TrimSpace(apiServer) == "" {
		return errors.New("apiserver address is empty")
	}
	if strings.TrimSpace(k8sCAPath) == "" && len(k8sCA) == 0 {
		return errors.New("kuberentes CA is empty")
	}

	// bootstrap token ID
	tokenID := sp[0]

	// create default options
	opts := clientcmd.NewDefaultPathOptions()

	// set config file path
	opts.LoadingRules.ExplicitPath = configPath

	// get string config
	cfg, err := opts.GetStartingConfig()
	if err != nil {
		return err
	}

	// create cluster
	cluster := clientcmdapi.NewCluster()
	cluster.Server = apiServer
	cluster.CertificateAuthority = k8sCAPath
	cluster.CertificateAuthorityData = k8sCA

	// set cluster
	cfg.Clusters[defaultCluster] = cluster

	// create auto info
	authInfo := clientcmdapi.NewAuthInfo()
	authInfo.Token = bootstrapToken

	// set auth info
	cfg.AuthInfos[fmt.Sprintf("%s:%s", bootstrapUserPrefix, tokenID)] = authInfo

	// create context
	ctx := clientcmdapi.NewContext()
	ctx.Cluster = defaultCluster
	ctx.AuthInfo = fmt.Sprintf("%s:%s", bootstrapUserPrefix, tokenID)

	// set context
	cfg.Contexts[defaultContext] = ctx
	cfg.CurrentContext = defaultContext

	// write to file
	return clientcmd.ModifyConfig(opts, *cfg, true)
}

func CreateKubeProxyConfig(apiServer, configPath, k8sCAPath, clientCertPath, clientKeyPath string, k8sCA, clientCert, clientKey []byte) error {

	if strings.TrimSpace(apiServer) == "" {
		return errors.New("apiserver address is empty")
	}
	if strings.TrimSpace(k8sCAPath) == "" && len(k8sCA) == 0 {
		return errors.New("kuberentes CA is empty")
	}
	if strings.TrimSpace(clientCertPath) == "" && len(clientCert) == 0 {
		return errors.New("kube-proxy client certificate is empty")
	}
	if strings.TrimSpace(clientKeyPath) == "" && len(clientKey) == 0 {
		return errors.New("kube-proxy client certificate key is empty")
	}

	// create default options
	opts := clientcmd.NewDefaultPathOptions()

	// set config file path
	opts.LoadingRules.ExplicitPath = configPath

	// get string config
	cfg, err := opts.GetStartingConfig()
	if err != nil {
		return err
	}

	// create cluster
	cluster := clientcmdapi.NewCluster()
	cluster.Server = apiServer
	cluster.CertificateAuthority = k8sCAPath
	cluster.CertificateAuthorityData = k8sCA

	// set cluster
	cfg.Clusters[defaultCluster] = cluster

	// create auto info
	authInfo := clientcmdapi.NewAuthInfo()
	authInfo.ClientCertificate = clientCertPath
	authInfo.ClientCertificateData = clientCert
	authInfo.ClientKey = clientKeyPath
	authInfo.ClientKeyData = clientKey

	// set auth info
	cfg.AuthInfos[kubeproxyUser] = authInfo

	// create context
	ctx := clientcmdapi.NewContext()
	ctx.AuthInfo = kubeproxyUser
	ctx.Cluster = defaultCluster

	// set context
	cfg.Contexts[defaultContext] = ctx
	cfg.CurrentContext = defaultContext

	// write to file
	return clientcmd.ModifyConfig(opts, *cfg, true)
}

func CreateAuditPolicy(configPath string) error {

	baseDir := filepath.Dir(configPath)
	if _, err := os.Stat(baseDir); err != nil {
		err = os.MkdirAll(baseDir, 0755)
		if err != nil {
			return err
		}
	}

	auditPolicy := viper.GetString("apiserver.audit_policy")

	configFile, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer configFile.Close()

	_, err = configFile.WriteString(auditPolicy)
	if err != nil {
		return err
	}

	return nil
}

func SetExampleData() {
	box := packr.NewBox("../resources")
	auditPolicy, err := box.FindString("apiserver/audit-policy.yaml")
	if err != nil {
		auditPolicy = ""
	}
	viper.SetDefault("apiserver.audit_policy", auditPolicy)
}
