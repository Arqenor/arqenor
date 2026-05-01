package grpcclient

import (
	"reflect"
	"testing"

	pb "arqenor/go/internal/grpc/generated"
	"arqenor/go/internal/scanner"
)

func TestPbHostToScannerHost_Nil(t *testing.T) {
	got := pbHostToScannerHost(nil)
	want := scanner.HostResult{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nil input: got %+v, want zero value", got)
	}
}

func TestPbHostToScannerHost_FullMapping(t *testing.T) {
	in := &pb.HostResult{
		Ip:       "10.0.0.42",
		Hostname: "host42.lan",
		MacAddr:  "aa:bb:cc:dd:ee:ff",
		IsUp:     true,
		OpenPorts: []*pb.PortResult{
			{
				Port:    22,
				Proto:   "tcp",
				State:   "open",
				Service: "ssh",
				Banner:  "SSH-2.0-OpenSSH_9.7",
			},
			{
				Port:  443,
				Proto: "tcp",
				State: "open",
			},
		},
	}

	got := pbHostToScannerHost(in)

	if got.IP != "10.0.0.42" {
		t.Errorf("IP: got %q, want 10.0.0.42", got.IP)
	}
	if got.Hostname != "host42.lan" {
		t.Errorf("Hostname: got %q", got.Hostname)
	}
	if got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC: got %q", got.MAC)
	}
	if !got.IsUp {
		t.Error("IsUp: got false, want true")
	}
	if len(got.Ports) != 2 {
		t.Fatalf("Ports len: got %d, want 2", len(got.Ports))
	}

	if got.Ports[0] != (scanner.PortResult{
		Port: 22, Proto: "tcp", State: "open",
		Service: "ssh", Banner: "SSH-2.0-OpenSSH_9.7",
	}) {
		t.Errorf("Ports[0]: got %+v", got.Ports[0])
	}

	if got.Ports[1].Port != 443 || got.Ports[1].Proto != "tcp" || got.Ports[1].State != "open" {
		t.Errorf("Ports[1]: got %+v", got.Ports[1])
	}
	if got.Ports[1].Service != "" || got.Ports[1].Banner != "" {
		t.Errorf("Ports[1]: empty fields should map to empty strings, got %+v", got.Ports[1])
	}
}

func TestPbHostToScannerHost_NoOpenPorts(t *testing.T) {
	in := &pb.HostResult{Ip: "192.168.1.1", IsUp: false}
	got := pbHostToScannerHost(in)

	if got.IP != "192.168.1.1" {
		t.Errorf("IP: got %q", got.IP)
	}
	if got.IsUp {
		t.Error("IsUp: should be false")
	}
	if got.Ports != nil {
		t.Errorf("Ports: expected nil, got %+v", got.Ports)
	}
}

func TestPbHostToScannerHost_SkipsNilPort(t *testing.T) {
	in := &pb.HostResult{
		Ip: "10.0.0.1",
		OpenPorts: []*pb.PortResult{
			nil,
			{Port: 80, Proto: "tcp", State: "open"},
			nil,
		},
	}
	got := pbHostToScannerHost(in)

	if len(got.Ports) != 1 {
		t.Fatalf("expected 1 port (nils filtered), got %d", len(got.Ports))
	}
	if got.Ports[0].Port != 80 {
		t.Errorf("got port %d, want 80", got.Ports[0].Port)
	}
}
