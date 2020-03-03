/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
)

// AddRootCAToMSP takes a root CA x509 certificate and adds it to the
// list of rootCerts for the specified application org MSP.
func AddRootCAToMSP(rootCA *x509.Certificate, orgName string, config *cb.Config) error {
	if (rootCA.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return errors.New("certificate KeyUsage must be x509.KeyUsageCertSign")
	}
	if !rootCA.IsCA {
		return errors.New("certificate must be a CA certificate")
	}

	applicationOrgs := getOrgsFromApplication(config)
	err := addRootCAToOrgMSP(rootCA, applicationOrgs[orgName])
	if err != nil {
		return fmt.Errorf("failed to add rootCA to application org: %v", err)
	}

	return nil
}

// addRootCAToOrgMSP adds a rootCA to org MSP config. It takes a pointer to
// org MSP config, and modifies in place.
func addRootCAToOrgMSP(rootCA *x509.Certificate, org *cb.ConfigGroup) error {
	configValue := org.Values[MSPKey]

	mspConfig := &mb.MSPConfig{}
	err := proto.Unmarshal(configValue.Value, mspConfig)
	if err != nil {
		return fmt.Errorf("unmarshalling mspConfig: %v", err)
	}

	fabricMSPConfig := &mb.FabricMSPConfig{}
	err = proto.Unmarshal(mspConfig.Config, fabricMSPConfig)
	if err != nil {
		return fmt.Errorf("unmarshalling mspConfig: %v", err)
	}

	buffer := bytes.NewBuffer(nil)
	err = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw})
	if err != nil {
		return err
	}
	fabricMSPConfig.RootCerts = append(fabricMSPConfig.RootCerts, buffer.Bytes())

	serializedMSPConfig, err := proto.Marshal(fabricMSPConfig)
	if err != nil {
		return fmt.Errorf("marshalling updated mspConfig: %v", err)
	}
	mspConfig.Config = serializedMSPConfig

	err = addValue(org, mspValue(mspConfig), AdminsPolicyKey)
	if err != nil {
		return err
	}

	return nil
}
