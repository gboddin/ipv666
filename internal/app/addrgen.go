package app

import (
	"github.com/google/gopacket/pcap"
	"github.com/lavalamp-/ipv666/internal/addressing"
	"github.com/lavalamp-/ipv666/internal/data"
	"github.com/lavalamp-/ipv666/internal/logging"
	"github.com/lavalamp-/ipv666/internal/modeling"
	"github.com/google/gopacket/routing"
	"github.com/spf13/viper"
	"log"
	"net"
	"time"
)

func RunAddrGen(modelPath string, outputPath string, fromNetwork string, genCount int) {
	clusterModel := &modeling.ClusterModel{}
	var err error


	if modelPath == "" {
		logging.Info("No model path specified. Using default model packaged with IPv666.")
		clusterModel, err = data.GetProbabilisticClusterModel()
	} else {
		logging.Infof("Using cluster model found at path '%s'.", modelPath)
		clusterModel, err = modeling.LoadModelFromFile(modelPath)
	}

	if err != nil {
		logging.ErrorF(err)
	}
	// Compute routing settings for public packets
	router, err := routing.New()
	if err != nil {
		log.Fatal(err)
	}
	// IP is google, selects the public interface
	clusterModel.Interface, _, clusterModel.IpSrc , err = router.Route(net.IP{0x2a, 0x00, 0x14, 0x50, 0x40, 0x13, 0x0c, 0x08 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68})
	if err != nil {
		log.Fatal(err)
	}
	// Open main interface handle for packets r/w
	clusterModel.PcapHandle, err = pcap.OpenLive(clusterModel.Interface.Name, 1024*256, true, 100*time.Nanosecond)
	if err != nil {
		log.Fatal(err)
	}
	defer clusterModel.PcapHandle.Close()
	// Define our BPFFilter to listen for ACK/SYN ( this is done in outside ipv666 for now and left for example )
	err = clusterModel.PcapHandle.SetBPFFilter("ip6 and port 32332")
	if err != nil {
		log.Fatal(err)
	}
	// YOU'LL HAVE TO FIND THIS FOR YOUR IPV6 GATEWAY
	clusterModel.HwDst, err = net.ParseMAC("00:00:00:00:02:f1")
	if err != nil {
		log.Fatal(err)
	}

	var generatedAddrs []*net.IP

	if fromNetwork == "" {
		logging.Info("No network specified. Generating addresses in the global address space.")
		generatedAddrs = clusterModel.GenerateAddresses(genCount, viper.GetFloat64("ModelGenerationJitter"))
	} else {
		_, ipnet, _ := net.ParseCIDR(fromNetwork)
		logging.Infof("Generating addresses in specified network range of '%s'.", ipnet)
		generatedAddrs, err = clusterModel.GenerateAddressesFromNetwork(genCount, viper.GetFloat64("ModelGenerationJitter"), ipnet)
		if err != nil {
			logging.ErrorF(err)
		}
	}

	logging.Infof("Successfully generated %d IP addresses. Writing results to file at path '%s'.", genCount, outputPath)

	err = addressing.WriteIPsToHexFile(outputPath, generatedAddrs)  //TODO allow users to specify what type of file to write

	if err != nil {
		logging.Error(err)
	}

	logging.Infof("Successfully wrote addresses to file '%s'.", outputPath)

}
