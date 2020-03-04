/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/tools/protolator"
	. "github.com/onsi/gomega"
)

func TestAddRootCAToMSP(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:     true,
	}

	channelGroup, err := baseApplicationChannelGroup()
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	err = AddRootCAToMSP(cert, "Org1", config)
	gt.Expect(err).ToNot(HaveOccurred())

	expectedConfig := `
	{
		"channel_group": {
			"groups": {
				"Application": {
					"groups": {
						"Org1": {
							"groups": {},
							"mod_policy": "Admins",
							"policies": {
								"Admins": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Admins"
										}
									},
									"version": "0"
								},
								"Endorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"LifecycleEndorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"Readers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Readers"
										}
									},
									"version": "0"
								},
								"Writers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Writers"
										}
									},
									"version": "0"
								}
							},
							"values": {
								"AnchorPeers": {
									"mod_policy": "Admins",
									"value": {
										"anchor_peers": [
											{
												"host": "host1",
												"port": 123
											}
										]
									},
									"version": "0"
								},
								"MSP": {
									"mod_policy": "Admins",
									"value": {
										"config": {
											"admins": [],
											"crypto_config": null,
											"fabric_node_ous": null,
											"intermediate_certs": [],
											"name": "",
											"organizational_unit_identifiers": [],
											"revocation_list": [],
											"root_certs": [
												"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
											],
											"signing_identity": null,
											"tls_intermediate_certs": [],
											"tls_root_certs": []
										},
										"type": 0
									},
									"version": "0"
								}
							},
							"version": "0"
						},
						"Org2": {
							"groups": {},
							"mod_policy": "Admins",
							"policies": {
								"Admins": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Admins"
										}
									},
									"version": "0"
								},
								"Endorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"LifecycleEndorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"Readers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Readers"
										}
									},
									"version": "0"
								},
								"Writers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Writers"
										}
									},
									"version": "0"
								}
							},
							"values": {
								"AnchorPeers": {
									"mod_policy": "Admins",
									"value": {
										"anchor_peers": [
											{
												"host": "host2",
												"port": 123
											}
										]
									},
									"version": "0"
								},
								"MSP": {
									"mod_policy": "Admins",
									"value": {
										"config": null,
										"type": 0
									},
									"version": "0"
								}
							},
							"version": "0"
						}
					},
					"mod_policy": "Admins",
					"policies": {
						"Admins": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "MAJORITY",
									"sub_policy": "Admins"
								}
							},
							"version": "0"
						},
						"Readers": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "ANY",
									"sub_policy": "Readers"
								}
							},
							"version": "0"
						},
						"Writers": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "ANY",
									"sub_policy": "Writers"
								}
							},
							"version": "0"
						}
					},
					"values": {
						"ACLs": {
							"mod_policy": "Admins",
							"value": {
								"acls": {
									"acl1": {
										"policy_ref": "hi"
									}
								}
							},
							"version": "0"
						},
						"Capabilities": {
							"mod_policy": "Admins",
							"value": {
								"capabilities": {
									"V1_3": {}
								}
							},
							"version": "0"
						}
					},
					"version": "0"
				}
			},
			"mod_policy": "",
			"policies": {},
			"values": {},
			"version": "0"
		},
		"sequence": "0"
	}
	`

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfig), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(config, expectedConfigProto)).To(BeTrue())
}

func TestAddRootCAToMSPFailure(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, err := baseApplicationChannelGroup()
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	tests := []struct {
		spec        string
		cert        *x509.Certificate
		expectedErr string
	}{
		{
			spec: "invalid key usage",
			cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageKeyAgreement,
			},
			expectedErr: "certificate KeyUsage must be x509.KeyUsageCertSign",
		},
		{
			spec: "certificate is not a CA",
			cert: &x509.Certificate{
				IsCA:     false,
				KeyUsage: x509.KeyUsageCertSign,
			},
			expectedErr: "certificate must be a CA certificate",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.spec, func(t *testing.T) {
			t.Parallel()
			gt := NewGomegaWithT(t)
			err = AddRootCAToMSP(tc.cert, "Org1", config)
			gt.Expect(err).To(MatchError(tc.expectedErr))
		})
	}
}

func TestRevokeCertificateFromMSP(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	channelGroup, err := baseApplicationChannelGroup()
	gt.Expect(err).ToNot(HaveOccurred())
	config := &cb.Config{
		ChannelGroup: channelGroup,
	}

	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	err = RevokeCertificateFromMSP(cert, "Org1", config)
	gt.Expect(err).ToNot(HaveOccurred())

	expectedConfig := `
	{
		"channel_group": {
			"groups": {
				"Application": {
					"groups": {
						"Org1": {
							"groups": {},
							"mod_policy": "Admins",
							"policies": {
								"Admins": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Admins"
										}
									},
									"version": "0"
								},
								"Endorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"LifecycleEndorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"Readers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Readers"
										}
									},
									"version": "0"
								},
								"Writers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Writers"
										}
									},
									"version": "0"
								}
							},
							"values": {
								"AnchorPeers": {
									"mod_policy": "Admins",
									"value": {
										"anchor_peers": [
											{
												"host": "host1",
												"port": 123
											}
										]
									},
									"version": "0"
								},
								"MSP": {
									"mod_policy": "Admins",
									"value": {
										"config": {
											"admins": [],
											"crypto_config": null,
											"fabric_node_ous": null,
											"intermediate_certs": [],
											"name": "",
											"organizational_unit_identifiers": [],
											"revocation_list": [
												"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
											],
											"root_certs": [],
											"signing_identity": null,
											"tls_intermediate_certs": [],
											"tls_root_certs": []
										},
										"type": 0
									},
									"version": "0"
								}
							},
							"version": "0"
						},
						"Org2": {
							"groups": {},
							"mod_policy": "Admins",
							"policies": {
								"Admins": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Admins"
										}
									},
									"version": "0"
								},
								"Endorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"LifecycleEndorsement": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "MAJORITY",
											"sub_policy": "Endorsement"
										}
									},
									"version": "0"
								},
								"Readers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Readers"
										}
									},
									"version": "0"
								},
								"Writers": {
									"mod_policy": "Admins",
									"policy": {
										"type": 3,
										"value": {
											"rule": "ANY",
											"sub_policy": "Writers"
										}
									},
									"version": "0"
								}
							},
							"values": {
								"AnchorPeers": {
									"mod_policy": "Admins",
									"value": {
										"anchor_peers": [
											{
												"host": "host2",
												"port": 123
											}
										]
									},
									"version": "0"
								},
								"MSP": {
									"mod_policy": "Admins",
									"value": {
										"config": null,
										"type": 0
									},
									"version": "0"
								}
							},
							"version": "0"
						}
					},
					"mod_policy": "Admins",
					"policies": {
						"Admins": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "MAJORITY",
									"sub_policy": "Admins"
								}
							},
							"version": "0"
						},
						"Readers": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "ANY",
									"sub_policy": "Readers"
								}
							},
							"version": "0"
						},
						"Writers": {
							"mod_policy": "Admins",
							"policy": {
								"type": 3,
								"value": {
									"rule": "ANY",
									"sub_policy": "Writers"
								}
							},
							"version": "0"
						}
					},
					"values": {
						"ACLs": {
							"mod_policy": "Admins",
							"value": {
								"acls": {
									"acl1": {
										"policy_ref": "hi"
									}
								}
							},
							"version": "0"
						},
						"Capabilities": {
							"mod_policy": "Admins",
							"value": {
								"capabilities": {
									"V1_3": {}
								}
							},
							"version": "0"
						}
					},
					"version": "0"
				}
			},
			"mod_policy": "",
			"policies": {},
			"values": {},
			"version": "0"
		},
		"sequence": "0"
	}
	`

	expectedConfigProto := &cb.Config{}
	err = protolator.DeepUnmarshalJSON(bytes.NewBufferString(expectedConfig), expectedConfigProto)
	gt.Expect(err).NotTo(HaveOccurred())

	gt.Expect(proto.Equal(config, expectedConfigProto)).To(BeTrue())
}
