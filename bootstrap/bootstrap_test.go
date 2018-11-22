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
	"fmt"
	"io/ioutil"
	"testing"
)

func Test_CreateBootstrapConfig(t *testing.T) {
	SetExampleData()
	id, secret := CreateBootstrapToken()
	token := fmt.Sprintf("%s.%s", id, secret)
	err := CreateBootstrapConfig("https://master1.kubernetes.node:6443", token, defaultBootstrapConfig, "/etc/kubernetes/ssl/kubernetes-root-ca.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_CreateKubeProxyConfig(t *testing.T) {
	SetExampleData()

	clientCert, err := ioutil.ReadFile("../auth/kubetool/ssl/kube-proxy.pem")
	if err != nil {
		t.Fatal(err)
	}

	clientCertKey, err := ioutil.ReadFile("../auth/kubetool/ssl/kube-proxy-key.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = CreateKubeProxyConfig("https://master1.kubernetes.node:6443", defaultKubeproxyConfig,
		"/etc/kubernetes/ssl/kubernetes-root-ca.pem",
		"",
		"",
		nil, clientCert, clientCertKey)

	if err != nil {
		t.Fatal(err)
	}
}

func Test_CreateAuditPolicy(t *testing.T) {
	SetExampleData()
	err := CreateAuditPolicy(defaultAuditPolicyConfig)
	if err != nil {
		t.Fatal(err)
	}
}
