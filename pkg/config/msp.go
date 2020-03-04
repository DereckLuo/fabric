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

	org := getOrgsFromApplication(config)[orgName]
	mspConfig, fabricMSPConfig, err := getMSPConfig(org)
	if err != nil {
		return fmt.Errorf("getting msp config: %v", err)
	}

	buffer := bytes.NewBuffer(nil)
	err = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Raw})
	if err != nil {
		return err
	}
	fabricMSPConfig.RootCerts = append(fabricMSPConfig.RootCerts, buffer.Bytes())

	err = addMSPConfigToOrg(org, mspConfig, fabricMSPConfig)
	if err != nil {
		return fmt.Errorf("adding msp config to org: %v", err)
	}

	return nil
}

func getMSPConfig(org *cb.ConfigGroup) (*mb.MSPConfig, *mb.FabricMSPConfig, error) {
	configValue := org.Values[MSPKey]

	mspConfig := &mb.MSPConfig{}
	err := proto.Unmarshal(configValue.Value, mspConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling mspConfig: %v", err)
	}

	fabricMSPConfig := &mb.FabricMSPConfig{}
	err = proto.Unmarshal(mspConfig.Config, fabricMSPConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshalling mspConfig: %v", err)
	}

	return mspConfig, fabricMSPConfig, nil
}

func addMSPConfigToOrg(org *cb.ConfigGroup, mspConfig *mb.MSPConfig, fabricMSPConfig *mb.FabricMSPConfig) error {
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

// RevokeCertificateFromMSP takes an x509 certificate and adds it to the
// revocation list for the specified application org MSP.
func RevokeCertificateFromMSP(cert *x509.Certificate, orgName string, config *cb.Config) error {
	org := getOrgsFromApplication(config)[orgName]
	mspConfig, fabricMSPConfig, err := getMSPConfig(org)
	if err != nil {
		return fmt.Errorf("getting msp config: %v", err)
	}

	// TODO validate that this certificate was issued by this MSP

	buffer := bytes.NewBuffer(nil)
	err = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return err
	}
	fabricMSPConfig.RevocationList = append(fabricMSPConfig.RevocationList, buffer.Bytes())

	err = addMSPConfigToOrg(org, mspConfig, fabricMSPConfig)
	if err != nil {
		return fmt.Errorf("adding msp config to org: %v", err)
	}

	return nil
}
