// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
  "os"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	setup()
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

var rootCmd = cobra.Command{
	Use:   "certificate-init-container",
	Short: "certificate-init-container handles the applicate side of CSR for K8s",
	Long: `Generates a TLS keypair, suitable for client and server auth, and submits
a request to the Kubernetes certificates endpoint. Then it polls for approval and
delivers the cert via a shared volume.`,
	RunE: operate,
}

func setup() {
	rootCmd.Flags().StringP("additional-dnsnames", "n", "", "additional dns names; comma separated")
	rootCmd.Flags().StringP("cert-dir", "d", "/etc/tls", "The directory where the TLS certs should be written")
	rootCmd.Flags().StringP("cluster-domain", "c", "cluster.local", "Kubernetes cluster domain")
	rootCmd.Flags().StringP("hostname", "H", "", "hostname as defined by pod.spec.hostname")
	rootCmd.Flags().StringP("namespace", "N", "default", "namespace as defined by pod.metadata.namespace")
	rootCmd.Flags().StringP("pod-name", "p", "", "name as defined by pod.metadata.name")
	rootCmd.Flags().StringP("pod-ip", "a", "", "IP address as defined by pod.status.podIP")
	rootCmd.Flags().StringP("service-names", "s", "", "service names that resolve to this Pod; comma separated")
	rootCmd.Flags().StringP("service-ips", "i", "", "service IP addresses that resolve to this Pod; comma separated")
	rootCmd.Flags().StringP("subdomain", "x", "", "subdomain as defined by pod.spec.subdomain")
}

func operate(cmd *cobra.Command, args []string) error {
	config := viper.New()
	config.BindPFlags(cmd.Flags())
	config.SetEnvPrefix("certinit")
	config.AutomaticEnv()

	additionalDNSNames := config.GetString("additional-dnsnames")
	certDir := config.GetString("cert-dir")
	clusterDomain := config.GetString("cluster-domain")
	hostname := config.GetString("hostname")
	namespace := config.GetString("namespace")
	podName := config.GetString("pod-name")
	podIP := config.GetString("pod-ip")
	serviceNames := config.GetString("service-names")
	serviceIPs := config.GetString("service-ips")
	subdomain := config.GetString("subdomain")

	certificateSigningRequestName := fmt.Sprintf("%s-%s", podName, namespace)

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return err
	}

	client, err := buildK8sClients()
	if err != nil {
		return err
	}

	key, err := genKey(certDir)
	if err != nil {
		return err
	}

	ipaddresses, err := assembleIPs(podIP, serviceIPs)
	if err != nil {
		return err
	}

	dnsNames := assembleDomainNames(podIP, hostname, subdomain, namespace, clusterDomain, additionalDNSNames, serviceNames)

	csrBytes, err := generateRequest(key, certDir, dnsNames, ipaddresses)
	if err != nil {
		return err
	}

	// Submit a certificate signing request, wait for it to be approved, then save
	// the signed certificate to the file system.
	certificateSigningRequest := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name:      certificateSigningRequestName,
			Namespace: namespace,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups:  []string{"system:authenticated"},
			Request: csrBytes,
			Usages: []certificates.KeyUsage{
				certificates.UsageDigitalSignature,
				certificates.UsageKeyEncipherment,
				certificates.UsageServerAuth,
				certificates.UsageClientAuth,
			},
		},
	}

	_, err = client.CertificatesV1beta1().CertificateSigningRequests().Create(certificateSigningRequest)
	if err != nil {
		return fmt.Errorf("unable to create the certificate signing request: %s", err)
	}

	certificate, err := seekApproval(client, certificateSigningRequestName)
	if err != nil {
		return fmt.Errorf("didn't receive signed certificate: %s", err)
	}

	certFile := path.Join(certDir, "tls.crt")
	if err := ioutil.WriteFile(certFile, certificate, 0600); err != nil {
		return fmt.Errorf("unable to write to %s: %s", certFile, err)
	}

	log.Printf("wrote %s", certFile)

	return nil
}

func buildK8sClients() (*k8s.Clientset, error) {
	k8scfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("%#v", err)
	}

	client, err := k8s.NewForConfig(k8scfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create a Kubernetes client: %s", err)
	}
	return client, nil
}

func genKey(certDir string) (*rsa.PrivateKey, error) {
	// Generate a private key, pem encode it, and save it to the filesystem.
	// The private key will be used to create a certificate signing request (csr)
	// that will be submitted to a Kubernetes CA to obtain a TLS certificate.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("unable to genarate the private key: %s", err)
	}

	pemKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	keyFile := path.Join(certDir, "tls.key")
	if err := ioutil.WriteFile(keyFile, pemKeyBytes, 0600); err != nil {
		return nil, fmt.Errorf("unable to write to %s: %s", keyFile, err)
	}

	log.Printf("wrote %s", keyFile)

	return key, nil
}

func assembleIPs(podIP, serviceIPs string) ([]net.IP, error) {
	// Gather the list of IP addresses for the certificate's IP SANs field which
	// include:
	//   - the pod IP address
	//   - 127.0.0.1 for localhost access
	//   - each service IP address that maps to this pod
	ip := net.ParseIP(podIP)
	if ip.To4() == nil && ip.To16() == nil {
		return nil, fmt.Errorf("invalid pod IP address")
	}

	ipaddresses := []net.IP{ip, net.ParseIP("127.0.0.1")}

	for _, s := range strings.Split(serviceIPs, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, fmt.Errorf("invalid service IP address")
		}
		ipaddresses = append(ipaddresses, ip)
	}

	return ipaddresses, nil
}

// Gather a list of DNS names that resolve to this pod which include the
// default DNS name:
//   - ${pod-ip-address}.${namespace}.pod.${cluster-domain}
//
// For each service that maps to this pod a dns name will be added using
// the following template:
//   - ${service-name}.${namespace}.svc.${cluster-domain}
//
// A dns name will be added for each additional DNS name provided via the
// `-additional-dnsnames` flag.
func assembleDomainNames(ip, hostname, subdomain, namespace, clusterDomain, additionalDNSNames, serviceNames string) []string {
	ns := []string{podDomainName(ip, namespace, clusterDomain)}
	if hostname != "" && subdomain != "" {
		ns = append(ns, podHeadlessDomainName(hostname, subdomain, namespace, clusterDomain))
	}

	for _, n := range strings.Split(additionalDNSNames, ",") {
		if n == "" {
			continue
		}
		ns = append(ns, n)
	}

	for _, n := range strings.Split(serviceNames, ",") {
		if n == "" {
			continue
		}
		ns = append(ns, serviceDomainName(n, namespace, clusterDomain))
	}

	return ns
}

func podDomainName(ip, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.pod.%s", strings.Replace(ip, ".", "-", -1), namespace, domain)
}

func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}

func serviceDomainName(name, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}

func generateRequest(key *rsa.PrivateKey, certDir string, dnsNames []string, ipaddresses []net.IP) ([]byte, error) {
	// Generate the certificate request, pem encode it, and save it to the filesystem.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dnsNames,
		IPAddresses:        ipaddresses,
	}

	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("unable to generate the certificate request: %s", err)
	}

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})

	csrFile := path.Join(certDir, "tls.csr")
	if err := ioutil.WriteFile(csrFile, certificateRequestBytes, 0600); err != nil {
		return nil, fmt.Errorf("unable to %s, error: %s", csrFile, err)
	}

	log.Printf("wrote %s", csrFile)

	return certificateRequestBytes, nil
}

func seekApproval(client *k8s.Clientset, certificateSigningRequestName string) ([]byte, error) {
	var certificate []byte

	log.Println("waiting for certificate...")
	for {
		csr, err := client.CertificatesV1beta1().CertificateSigningRequests().Get(certificateSigningRequestName, v1.GetOptions{})
		if err != nil {
			log.Printf("unable to retrieve certificate signing request (%s): %s", certificateSigningRequestName, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(csr.Status.Conditions) > 0 {
			if csr.Status.Conditions[0].Type == certificates.CertificateApproved {
				certificate = csr.Status.Certificate
				return certificate, nil
			}
		}

		log.Printf("certificate signing request (%s) not approved; trying again in 5 seconds", certificateSigningRequestName)

		time.Sleep(5 * time.Second)
	}
}
