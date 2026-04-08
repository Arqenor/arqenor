package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HostResult holds scan results for one discovered host.
type HostResult struct {
	IP       string
	Hostname string
	MAC      string
	IsUp     bool
	Ports    []PortResult
}

// PortResult holds the result for one scanned port.
type PortResult struct {
	Port    int
	Proto   string // "tcp" | "udp"
	State   string // "open" | "closed" | "filtered"
	Service string
	Banner  string
}

// Scanner is the main network scanning engine.
type Scanner struct {
	logger      *zap.Logger
	workerCount int
	timeout     time.Duration
}

func New(logger *zap.Logger) *Scanner {
	return &Scanner{
		logger:      logger,
		workerCount: 256,
		timeout:     2 * time.Second,
	}
}

// ScanCIDR discovers live hosts in a CIDR range and scans them.
func (s *Scanner) ScanCIDR(ctx context.Context, cidr string, ports []int) ([]HostResult, error) {
	ips, err := hostsInCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}

	s.logger.Info("starting scan", zap.String("cidr", cidr), zap.Int("hosts", len(ips)))

	results := make([]HostResult, 0, len(ips))
	var mu sync.Mutex

	sem := make(chan struct{}, s.workerCount)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := s.scanHost(ctx, target, ports)
			if result.IsUp {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	s.logger.Info("scan complete", zap.Int("up", len(results)))
	return results, nil
}

func (s *Scanner) scanHost(ctx context.Context, ip string, ports []int) HostResult {
	result := HostResult{IP: ip}

	// TCP connect check on port 80/443/22 to determine if host is up
	probes := []int{80, 443, 22, 3389}
	for _, p := range probes {
		addr := fmt.Sprintf("%s:%d", ip, p)
		conn, err := net.DialTimeout("tcp", addr, s.timeout)
		if err == nil {
			conn.Close()
			result.IsUp = true
			break
		}
	}

	if !result.IsUp {
		return result
	}

	// Reverse DNS
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	// Port scan
	if len(ports) > 0 {
		result.Ports = s.scanPorts(ctx, ip, ports)
	}

	return result
}

func (s *Scanner) scanPorts(ctx context.Context, ip string, ports []int) []PortResult {
	results := make([]PortResult, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, s.timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			pr := PortResult{
				Port:  p,
				Proto: "tcp",
				State: "open",
			}

			// Basic banner grab
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			if n > 0 {
				pr.Banner = string(buf[:n])
			}

			mu.Lock()
			results = append(results, pr)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

// hostsInCIDR enumerates all host IPs in a CIDR block.
func hostsInCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast address
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
