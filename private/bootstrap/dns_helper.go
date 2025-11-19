// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bootstrap

import (
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	scionDiscoveryService = "x-sciondiscovery:tcp"
	scionDiscoveryTXTKey  = "x-sciondiscovery"
)

// GetScionDiscoveryAddress performs NAPTR DNS lookup for SCION discovery.
// It looks for NAPTR records with service "x-sciondiscovery:tcp" and extracts
// the replacement address and port from TXT records.
func GetScionDiscoveryAddress(hostName string) (string, error) {
	// Ensure hostname ends with a dot for DNS queries
	if !strings.HasSuffix(hostName, ".") {
		hostName = hostName + "."
	}

	// Lookup NAPTR records
	naptrRecords, err := lookupNAPTR(hostName)
	if err != nil {
		log.Debug("Checking discovery service NAPTR: lookup failed", "host", hostName, "err", err)
		return "", serrors.Wrap("NAPTR lookup failed", err, "host", hostName)
	}

	if len(naptrRecords) == 0 {
		log.Debug("Checking discovery service NAPTR: no records found", "host", hostName)
		return "", serrors.New("no NAPTR records found", "host", hostName)
	}

	// Iterate through NAPTR records looking for x-sciondiscovery:tcp service
	for _, naptr := range naptrRecords {
		naptrService := strings.ToLower(naptr.Service)

		// Look for x-sciondiscovery:tcp service
		if naptrService != scionDiscoveryService {
			continue
		}

		naptrFlag := strings.ToUpper(naptr.Flags)
		replacement := naptr.Replacement

		// Get port from TXT record
		port, err := getScionDiscoveryPort(hostName)
		if err != nil {
			log.Debug("Failed to get discovery port", "host", hostName, "err", err)
			continue
		}

		// Handle A flag - IPv4 address
		if naptrFlag == "A" {
			addr, err := queryA(replacement)
			if err != nil {
				log.Debug("Failed to resolve A record", "replacement", replacement, "err", err)
				continue
			}
			return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
		}

		// Handle AAAA flag - IPv6 address
		if naptrFlag == "AAAA" {
			addr, err := queryAAAA(replacement)
			if err != nil {
				log.Debug("Failed to resolve AAAA record", "replacement", replacement, "err", err)
				continue
			}
			// For IPv6, JoinHostPort automatically wraps in brackets
			return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
		}

		// Continue to collect more hints if flags don't match
	}

	return "", serrors.New("no suitable NAPTR record found", "host", hostName)
}

// getScionDiscoveryPort queries TXT records to find the port for SCION discovery service.
// It looks for a TXT record with format "x-sciondiscovery=<port>".
// This mirrors the Java implementation in DNSHelper.getScionDiscoveryPort.
func getScionDiscoveryPort(hostName string) (int, error) {
	txtRecords, err := lookupTXT(hostName)
	if err != nil {
		return 0, serrors.Wrap("TXT lookup failed", err, "host", hostName)
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, scionDiscoveryTXTKey+"=") {
			portStr := strings.TrimPrefix(txt, scionDiscoveryTXTKey+"=")
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Info("Error parsing TXT entry", "entry", txt, "err", err)
				continue
			}
			if port < 0 || port > 65535 {
				log.Info("Error parsing TXT entry: invalid port", "entry", txt, "port", port)
				continue
			}
			return port, nil
		}
	}

	return 0, serrors.New("could not find valid TXT x-sciondiscovery record", "host", hostName)
}

// queryA performs an A record DNS query and returns the first address.
// This mirrors the Java implementation in DNSHelper.queryA.
func queryA(hostName string) (net.IP, error) {
	ips, err := lookupA(hostName)
	if err != nil || len(ips) == 0 {
		return nil, serrors.New("no DNS A entry found", "host", hostName)
	}
	// Just return the first one for now
	return ips[0], nil
}

// queryAAAA performs an AAAA record DNS query and returns the first address.
// This mirrors the Java implementation in DNSHelper.queryAAAA.
func queryAAAA(hostName string) (net.IP, error) {
	ips, err := lookupAAAA(hostName)
	if err != nil || len(ips) == 0 {
		return nil, serrors.New("no DNS AAAA entry found", "host", hostName)
	}
	// Just return the first one for now
	return ips[0], nil
}

// lookupNAPTR performs a NAPTR DNS query.
func lookupNAPTR(name string) ([]*dns.NAPTR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeNAPTR)

	client := &dns.Client{}
	resp, _, err := client.Exchange(msg, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return nil, err
	}

	var records []*dns.NAPTR
	for _, ans := range resp.Answer {
		if naptr, ok := ans.(*dns.NAPTR); ok {
			records = append(records, naptr)
		}
	}

	return records, nil
}

// lookupTXT performs a TXT DNS query.
func lookupTXT(name string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeTXT)

	client := &dns.Client{}
	resp, _, err := client.Exchange(msg, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			// Concatenate all strings in the TXT record
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	return records, nil
}

// lookupA performs an A record DNS query.
func lookupA(name string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)

	client := &dns.Client{}
	resp, _, err := client.Exchange(msg, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	return ips, nil
}

// lookupAAAA performs an AAAA record DNS query.
func lookupAAAA(name string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)

	client := &dns.Client{}
	resp, _, err := client.Exchange(msg, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA)
		}
	}

	return ips, nil
}
