/*
Copyright IBM Corp All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package devmode

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("Devmode", func() {
	var (
		testDir          string
		client           *docker.Client
		network          *nwo.Network
		process          ifrit.Process
		chaincode        nwo.Chaincode
		legacyChaincode  nwo.Chaincode
		chaincodeRunner  *ginkgomon.Runner
		chaincodeProcess ifrit.Process
		channelName      string
	)

	BeforeEach(func() {
		var err error
		channelName = "testchannel"
		testDir, err = ioutil.TempDir("", "devmode")
		Expect(err).NotTo(HaveOccurred())

		client, err = docker.NewClientFromEnv()
		Expect(err).NotTo(HaveOccurred())

		// network = nwo.New(nwo.BasicSolo(), testDir, client, StartPort(), components)
		network = nwo.New(nwo.SimpleSolo(), testDir, client, StartPort(), components)
		network.TLSEnabled = false
		// turn on dev mode for all peers
		for _, p := range network.Peers {
			p.DevMode = true
		}

		network.GenerateConfigTree()
		network.Bootstrap()

		networkRunner := network.NetworkGroupRunner()
		process = ifrit.Invoke(networkRunner)
		Eventually(process.Ready(), network.EventuallyTimeout).Should(BeClosed())
	})

	AfterEach(func() {
		if process != nil {
			process.Signal(syscall.SIGTERM)
			Eventually(process.Wait(), network.EventuallyTimeout).Should(Receive())
		}

		if chaincodeProcess != nil {
			chaincodeProcess.Signal(syscall.SIGTERM)
		}

		if network != nil {
			network.Cleanup()
		}

		os.RemoveAll(testDir)
	})

	It("executes chaincode in dev mode using legacy lifecycle", func() {
		legacyChaincode = nwo.Chaincode{
			Name:    "mycc",
			Version: "0.0",
			Path:    "github.com/hyperledger/fabric/integration/chaincode/simple/cmd",
			Ctor:    `{"Args":["init","a","100","b","200"]}`,
			Policy:  `AND ('Org1MSP.member','Org2MSP.member')`,
		}
		legacyChaincodeID := fmt.Sprintf("%s:%s", legacyChaincode.Name, legacyChaincode.Version)

		org1peer0 := network.Peer("Org1", "peer0")
		peers := network.PeersWithChannel(channelName)
		orderer := network.Orderer("orderer")

		By("setting up the channel")
		network.CreateAndJoinChannel(orderer, channelName)

		By("building chaincode")
		chaincodeExecutePath := components.Build(legacyChaincode.Path)

		By("running the chaincode")
		peerChaincodeAddress := network.PeerAddress(org1peer0, nwo.ChaincodePort)
		flags := []string{"-peer.address", peerChaincodeAddress}
		envs := []string{
			"CORE_PEER_TLS_ENABLED=false",
			fmt.Sprintf("CORE_PEER_ADDRESS=%s", peerChaincodeAddress),
			fmt.Sprintf("CORE_CHAINCODE_ID_NAME=%s", legacyChaincodeID),
		}

		cmd := exec.Command(chaincodeExecutePath, []string{"-peer.address", peerChaincodeAddress}...)
		cmd.Env = append(cmd.Env, envs...)
		chaincodeRunner = ginkgomon.New(ginkgomon.Config{
			Name:              "chaincode",
			Command:           cmd,
			StartCheckTimeout: 15 * time.Second,
		})
		chaincodeProcess = ifrit.Invoke(chaincodeRunner)
		Eventually(chaincodeProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

		By("installing the chaincode")
		nwo.InstallChaincodeLegacy(network, legacyChaincode, peers...)
		By("Instantiating the chaincode")
		nwo.InstantiateChaincodeLegacy(network, channelName, orderer, legacyChaincode, org1peer0, peers...)
		By("Querying and invoking the chaincode")
		RunQueryInvokeQuery(network, orderer, org1peer0, channelName, 100)

		By("killing chaincode process")
		chaincodeProcess.Signal(syscall.SIGKILL)
		Eventually(chaincodeProcess.Wait(), network.EventuallyTimeout).Should(Receive())

		By("querying chaincode after it is being killed")
		sess, err := network.PeerUserSession(org1peer0, "User1", commands.ChaincodeQuery{
			ChannelID: channelName,
			Name:      "mycc",
			Ctor:      `{"Args":["query","a"]}`,
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
		Expect(sess).To(gbytes.Say(strconv.Itoa(90)))

		By("restarting the chaincode process")
		cmd = exec.Command(chaincodeExecutePath, flags...)
		cmd.Env = append(cmd.Env, envs...)
		chaincodeRunner = ginkgomon.New(ginkgomon.Config{
			Name:              "chaincode",
			Command:           cmd,
			StartCheckTimeout: 15 * time.Second,
		})
		chaincodeProcess = ifrit.Invoke(chaincodeRunner)
		Eventually(chaincodeProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

		By("querying and invoking the chaincode")
		RunQueryInvokeQuery(network, orderer, org1peer0, channelName, 90)
	})

	FIt("executes chaincode in dev mode", func() {
		chaincode = nwo.Chaincode{
			Name:        "mycc",
			Version:     "0.0",
			Path:        components.Build("github.com/hyperledger/fabric/integration/chaincode/simple/cmd"),
			Lang:        "binary",
			PackageFile: filepath.Join(testDir, "simplecc.tar.gz"),
			Ctor:        `{"Args":["init","a","100","b","200"]}`,
			// SignaturePolicy: `OR ('Org1MSP.member','Org2MSP.member')`,
			SignaturePolicy: `OR ('Org1MSP.member')`,
			Sequence:        "1",
			InitRequired:    true,
			Label:           "my_prebuilt_chaincode",
		}

		org1peer0 := network.Peer("Org1", "peer0")
		// peers := network.PeersWithChannel(channelName)
		orderer := network.Orderer("orderer")

		By("setting up the channel")
		network.CreateAndJoinChannel(orderer, channelName)

		By("enable new lifecycle capabilities")
		// nwo.EnableCapabilities(network, "testchannel", "Application", "V2_0", orderer, network.Peer("Org1", "peer0"), network.Peer("Org2", "peer0"))
		nwo.EnableCapabilities(network, "testchannel", "Application", "V2_0", orderer, org1peer0)

		// By("packaging and installing chaincode")
		// nwo.PackageAndInstallChaincode(network, chaincode, peers...)
		// chaincode.SetPackageIDFromPackageFile()

		By("setting chaincode id to expected devmode id")
		chaincodeID := fmt.Sprintf("%s:%s", chaincode.Name, chaincode.Version)

		By("running the chaincode")
		peerChaincodeAddress := network.PeerAddress(org1peer0, nwo.ChaincodePort)
		envs := []string{
			"CORE_PEER_TLS_ENABLED=false",
			fmt.Sprintf("CORE_PEER_ADDRESS=%s", peerChaincodeAddress),
			fmt.Sprintf("CORE_CHAINCODE_ID_NAME=%s", chaincodeID),
		}

		cmd := exec.Command(chaincode.Path, []string{"-peer.address", peerChaincodeAddress}...)
		cmd.Env = append(cmd.Env, envs...)
		chaincodeRunner = ginkgomon.New(ginkgomon.Config{
			Name:    "chaincode",
			Command: cmd,
			// StartCheck:        `starting up ...`,
			StartCheckTimeout: 15 * time.Second,
		})
		chaincodeProcess = ifrit.Invoke(chaincodeRunner)
		Eventually(chaincodeProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

		By("approving chaincode for orgs")
		nwo.ApproveChaincodeForMyOrg(network, channelName, orderer, chaincode, org1peer0)
		By("committing chaincode")
		nwo.CheckCommitReadinessUntilReady(network, channelName, chaincode, network.PeerOrgs(), org1peer0)
		nwo.CommitChaincode(network, channelName, orderer, chaincode, org1peer0)
		By("init chaincode if required")
		nwo.InitChaincode(network, channelName, orderer, chaincode, org1peer0)

		By("Querying and invoking the chaincode")
		RunQueryInvokeQuery(network, orderer, org1peer0, channelName, 100)

		By("killing chaincode process")
		chaincodeProcess.Signal(syscall.SIGKILL)
		Eventually(chaincodeProcess.Wait(), network.EventuallyTimeout).Should(Receive(MatchError("exit status 137")))

		By("restarting the chaincode process")
		cmd = exec.Command(chaincode.Path, []string{"-peer.address", peerChaincodeAddress}...)
		cmd.Env = append(cmd.Env, envs...)
		chaincodeRunner = ginkgomon.New(ginkgomon.Config{
			Name:              "chaincode",
			Command:           cmd,
			StartCheckTimeout: 15 * time.Second,
		})
		chaincodeProcess = ifrit.Invoke(chaincodeRunner)
		Eventually(chaincodeProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

		By("querying and invoking the chaincode")
		RunQueryInvokeQuery(network, orderer, org1peer0, channelName, 90)
	})
})

func RunQueryInvokeQuery(n *nwo.Network, orderer *nwo.Orderer, peer *nwo.Peer, channel string, queryValue int) {
	By("querying the chaincode")
	sess, err := n.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: channel,
		Name:      "mycc",
		Ctor:      `{"Args":["query","a"]}`,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess).To(gbytes.Say(strconv.Itoa(queryValue)))

	By("invoke the chaincode")
	sess, err = n.PeerUserSession(peer, "User1", commands.ChaincodeInvoke{
		ChannelID: channel,
		Orderer:   n.OrdererAddress(orderer, nwo.ListenPort),
		Name:      "mycc",
		Ctor:      `{"Args":["invoke","a","b","10"]}`,
		PeerAddresses: []string{
			n.PeerAddress(n.Peer("Org1", "peer0"), nwo.ListenPort),
			// n.PeerAddress(n.Peer("Org2", "peer0"), nwo.ListenPort),
		},
		WaitForEvent: true,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess.Err).To(gbytes.Say("Chaincode invoke successful. result: status:200"))

	By("querying the chaincode again")
	sess, err = n.PeerUserSession(peer, "User1", commands.ChaincodeQuery{
		ChannelID: channel,
		Name:      "mycc",
		Ctor:      `{"Args":["query","a"]}`,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(0))
	Expect(sess).To(gbytes.Say(strconv.Itoa(queryValue - 10)))
}
