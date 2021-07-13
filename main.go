// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"tbd/admind-sdks/go/admindapi"
	"tbd/admind/models"
	"tbd/cfgdist/kvstores/emitter"
	"tbd/go-shared/logs"
	"tbd/go-shared/nsqbatch"
	"tbd/go-shared/pidfile"
	version "tbd/go-version"

	"tbd/l3afd/config"
	"tbd/l3afd/kf"
	"tbd/l3afd/stats"
)

const daemonName = "l3afd"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs.Infof("%s started.", daemonName)

	var confPath string
	flag.StringVar(&confPath, "config", "config/l3afd.cfg", "config path")

	flag.Parse()
	version.Init()
	conf, err := config.ReadConfig(confPath)
	logs.IfFatalLogf(err, "Unable to parse config", confPath)

	logs.IfFatalLogf(pidfile.CheckPIDConflict(conf.PIDFilename), "The PID file: %s, is in an unacceptable state", conf.PIDFilename)
	logs.IfFatalLogf(pidfile.CreatePID(conf.PIDFilename), "The PID file: %s, could not be created", conf.PIDFilename)

	logs.IfFatalLogf(checkKernelVersion(conf), "The unsupported kernel version please upgrade")

	if conf.AdmindApiEnabled {
		logs.IfErrorLogf(registerL3afD(conf), "L3afd registration failed")
	}

	kfConfigs, err := NFConfigsFromCDB(ctx, conf)
	logs.IfFatalLogf(err, "L3afd failed to start", err)

	if conf.EBPFChainDebugEnabled {
		kf.SetupKFDebug(conf.EBPFChainDebugAddr, kfConfigs)
	}
	select {}
}

func NFConfigsFromCDB(ctx context.Context, conf *config.Config) (*kf.NFConfigs, error) {
	// Get Hostname
	machineHostname, err := os.Hostname()
	logs.IfErrorLogf(err, "Could not get hostname from OS")

	// setup Metrics endpoint
	stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)

	var producer nsqbatch.Producer
	if prefs := nsqbatch.GetSystemPrefs(); prefs.Enabled {
		producer, err = nsqbatch.NewProducer(prefs)
		if err != nil {
			logs.Errorf("could not set up nsqd: Details %s", err)
			return nil, fmt.Errorf("could not set up nsqd: %v", err)
		}
	}
	netNamespace := os.Getenv("TBNETNAMESPACE")
	cdbKVStore, err := kf.VersionAnnouncerFromCDB(ctx, machineHostname,
		daemonName, netNamespace, conf.CDBFilename, conf.DataCenter, "", false, false, producer)
	if err != nil {
		return nil, fmt.Errorf("error in version announcer: %v", err)
	}
	emit := emitter.NewKVStoreChangeEmitter(cdbKVStore)
	pMon := kf.NewpCheck(conf.MaxNFReStartCount, conf.BpfChainingEnabled, conf.KFPollInterval)
	kfM := kf.NewpKFMetrics(conf.BpfChainingEnabled, conf.NMetricSamples)

	nfConfigs, err := kf.NewNFConfigs(ctx, emit, machineHostname, conf, pMon, kfM)
	if err != nil {
		return nil, fmt.Errorf("error in NewNFConfigs setup: %v", err)
	}
	pidfile.SetupGracefulShutdown(func() error {
		if len(nfConfigs.IngressXDPBpfs) > 0 || len(nfConfigs.IngressTCBpfs) > 0 || len(nfConfigs.EgressTCBpfs) > 0 {
			ctx, cancelfunc := context.WithTimeout(context.Background(), conf.ShutdownTimeout*time.Second)
			defer cancelfunc()
			logs.IfErrorLogf(nfConfigs.Close(ctx), "stopping all network functions failed")
		}
		logs.IfErrorLogf(emit.Close(), "kv store emit close failed")
		return nil
	}, conf.ShutdownTimeout, conf.PIDFilename)
	return nfConfigs, nil
}

func getHostNetwork() ([]models.L3afDHostInterface, error) {
	var hostIfaces = make([]models.L3afDHostInterface, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Failed to get net interfaces: %v", err)
	}
	// handle err
	for _, iface := range ifaces {
		var elem models.L3afDHostInterface
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		elem.IfaceName = iface.Name
		addrs, _ := iface.Addrs()
		elem.MacAddress = iface.HardwareAddr.String()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			elem.IPv4Address = ip.String()
			break
		}
		hostIfaces = append(hostIfaces, elem)
	}
	return hostIfaces, nil
}

func checkKernelVersion(conf *config.Config) error {
	const minVerLen = 2

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return fmt.Errorf("Failed to find kernel version: %v", err)
	}

	//validate version
	ver := strings.Split(kernelVersion, ".")
	if len(ver) < minVerLen {
		return fmt.Errorf("Expected minimum kernel version length %d and got %d, ver %+q", minVerLen, len(ver), ver)
	}
	major_ver, err := strconv.Atoi(ver[0])
	if err != nil {
		return fmt.Errorf("Failed to find kernel major version: %v", err)
	}
	minor_ver, err := strconv.Atoi(ver[1])
	if err != nil {
		return fmt.Errorf("Failed to find kernel minor version: %v", err)
	}

	if major_ver > conf.MinKernelMajorVer {
		return nil
	}
	if major_ver == conf.MinKernelMajorVer && minor_ver >= conf.MinKernelMinorVer {
		return nil
	}

	return fmt.Errorf("Expected Kernel version >=  %d.%d", conf.MinKernelMajorVer, conf.MinKernelMinorVer)
}

// registerL3afD defines add entry in AdminD
// In case of conflict - duplicate entry, will continue
func registerL3afD(conf *config.Config) error {

	// Get Hostname
	machineHostname, err := os.Hostname()
	logs.IfErrorLogf(err, "Could not get hostname from OS")
	// Kernel version is validated once, so we are assuming we have supported version
	kernelVersion, _ := getKernelVersion()
	l3afdHostIfaces, err := getHostNetwork()
	logs.IfFatalLogf(err, "Could not get network interfaces from OS")

	l3afdHost := &models.NewL3afDHostRequest{
		Name:          machineHostname,
		Description:   "New l3af deamon host",
		KernelVersion: kernelVersion,
		NetInterfaces: l3afdHostIfaces,
		GroupID:       conf.AdmindGroupID,
	}

	buf, err := json.Marshal(l3afdHost)
	if err != nil {
		return fmt.Errorf("Failed to marshal l3afd host data: %v", err)
	}

	api, err := admindapi.NewAPI(conf.AdmindUsername, conf.AdmindApiKey, conf.AdmindHost)
	if err != nil {
		logs.Fatalf("Could not create admind api handle. Error %s", err)
	}

	resp, err := api.POST(&admindapi.Req{URI: "/api/v2/l3afd/hosts", Body: string(buf)})

	if err != nil && resp.HTTPResponse().StatusCode == http.StatusConflict {
		logs.Warningf("POST request for l3afd hosts already registered.")
		if err = updateL3afDHost(api, l3afdHost); err != nil {
			logs.Errorf("L3afd Host update failed %v", err)
		}
		return nil
	}
	defer resp.HTTPResponse().Body.Close()

	if err != nil {
		logs.Fatalf("POST or PUT request for l3afd hosts returned unexpected errors %s\n", err)
		return err
	}

	buff := resp.Body()
	if resp.HTTPResponse().StatusCode != http.StatusOK {
		return fmt.Errorf("POST request for l3afd hosts returned unexpected status code: %d (%s), %d was expected\n\tResponse Body: %s\n", resp.HTTPResponse().StatusCode, http.StatusText(resp.HTTPResponse().StatusCode), http.StatusOK, string(buff))
	}

	logs.Infof("L3af daemon registered successfully.")
	return nil
}

// This method get the id of the existing L3afd host entity and updates Kernel Version, IP Address and Mac Address in DB
// This will not add any new HW changes (i.e. new NIC)

func updateL3afDHost(api *admindapi.API, l3afdHost *models.NewL3afDHostRequest) error {
	type readL3afDHostResponse struct {
		L3afDHostData []models.L3afDHostData `json:"l3afd_host_data"`
	}

	var hostDataResp readL3afDHostResponse

	resp, err := api.GET(&admindapi.Req{URI: "/api/v2/l3afd/hosts/by-name/" + l3afdHost.Name})
	if err != nil {
		return fmt.Errorf("Get L3afd Host details by-name failed: %v", err)
	}
	defer resp.HTTPResponse().Body.Close()

	if resp.HTTPResponse().StatusCode != http.StatusOK {
		return fmt.Errorf("Get request for l3afd hosts returned unexpected status code: %d (%s), %d was expected\n", resp.HTTPResponse().StatusCode, http.StatusText(resp.HTTPResponse().StatusCode), http.StatusOK)
	}

	if err = json.Unmarshal(resp.Body(), &hostDataResp); err != nil {
		return fmt.Errorf("Get L3afd Host details by-name unmarshal failed: %v", err)
	}

	newHostData := &models.L3afDHostData{
		L3afDHost: models.L3afDHost{
			Name:          l3afdHost.Name,
			Description:   "Updated by L3af deamon host",
			KernelVersion: l3afdHost.KernelVersion,
			IsEnabled:     true,
		},
		NetInterfaces: l3afdHost.NetInterfaces,
	}

	buf, err := json.Marshal(newHostData)
	if err != nil {
		return fmt.Errorf("Failed to marshal l3afd host data: %v", err)
	}
	URI := fmt.Sprintf("/api/v2/l3afd/hosts/%d", hostDataResp.L3afDHostData[0].ID)
	resp, err = api.PUT(&admindapi.Req{URI: URI, Body: string(buf)})
	if err != nil {
		return fmt.Errorf("Update L3afd Host details failed: %v", err)
	}

	if resp.HTTPResponse().StatusCode != http.StatusOK {
		return fmt.Errorf("PUT request for l3afd hosts returned unexpected status code: %d (%s), %d was expected\n", resp.HTTPResponse().StatusCode, http.StatusText(resp.HTTPResponse().StatusCode), http.StatusOK)
	}

	logs.Infof("L3af daemon updated successfully.")
	return nil
}

func getKernelVersion() (string, error) {
	osVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("Failed to read procfs: %v", err)
	}
	var u1, u2, kernelVersion string
	_, err = fmt.Sscanf(string(osVersion), "%s %s %s", &u1, &u2, &kernelVersion)
	if err != nil {
		return "", fmt.Errorf("Failed to scan procfs version: %v", err)
	}

	return kernelVersion, nil
}
