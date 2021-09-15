// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
// +build admind
//

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	"walmart-internal/admind-sdks/go/admindapi"
	"walmart-internal/admind/models"
	"walmart-internal/l3afd/config"

	"github.com/rs/zerolog/log"
)

// registerL3afD defines add entry in AdminD
// In case of conflict - duplicate entry, will continue
func registerL3afD(conf *config.Config) error {
	// The special case of beacon nodes, admind api is not accessible then return nil
	if !conf.AdmindApiEnabled {
		return nil
	}

	// Get Hostname
	machineHostname, err := os.Hostname()
	if err != nil {
		log.Error().Err(err).Msg("Could not get hostname from OS")
	}
	// Kernel version is validated once, so we are assuming we have supported version
	kernelVersion, _ := getKernelVersion()
	l3afdHostIfaces, err := getHostNetwork()
	if err != nil {
		log.Fatal().Err(err).Msg("Could not get network interfaces from OS")
	}

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
		log.Fatal().Err(err).Msg("Could not create admind api handle")
	}

	resp, err := api.POST(&admindapi.Req{URI: "/api/v2/l3afd/hosts", Body: string(buf)})

	if err != nil && resp.HTTPResponse().StatusCode == http.StatusConflict {
		log.Warn().Msg("POST request for l3afd hosts already registered")
		if err = updateL3afDHost(api, l3afdHost); err != nil {
			log.Error().Err(err).Msg("L3afd Host update failed")
		}
		return nil
	}
	defer resp.HTTPResponse().Body.Close()

	if err != nil {
		log.Fatal().Err(err).Msg("POST or PUT request for l3afd hosts returned unexpected errors")
		return err
	}

	buff := resp.Body()
	if resp.HTTPResponse().StatusCode != http.StatusOK {
		return fmt.Errorf("POST request for l3afd hosts returned unexpected status code: %d (%s), %d was expected\n\tResponse Body: %s\n", resp.HTTPResponse().StatusCode, http.StatusText(resp.HTTPResponse().StatusCode), http.StatusOK, string(buff))
	}

	log.Info().Msg("L3af daemon registered successfully.")
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

	log.Info().Msg("L3af daemon updated successfully.")
	return nil
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
