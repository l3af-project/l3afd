package decode

import (
	"fmt"
	"net"
)

type IPV4Field struct {
	name  string
	Value net.IP
}

func (f *IPV4Field) Name() string { return f.name }
func (f *IPV4Field) Align() int   { return 4 }
func (f *IPV4Field) Size() int    { return 4 }

func NewIPV4Field(name string, value net.IP) *IPV4Field {
	if value == nil {
		value = net.IPv4zero
	}
	return &IPV4Field{name: name, Value: value}
}
func (f *IPV4Field) Serialize() ([]byte, error) {
	ip4 := f.Value.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	return ip4, nil
}

func (f *IPV4Field) Deserialize(buf []byte, offset int) (int, error) {
	f.Value = net.IP(buf[offset : offset+4])
	return offset + 4, nil
}
