package decode

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// ------------------- Utilities -------------------

// utility function to align an offset to a given alignment
func align(offset, alignment int) int {
	if offset%alignment == 0 {
		return offset
	}
	return offset + (alignment - (offset % alignment))
}

// utility function to check if the system is little-endian
func IsLittleEndian() bool {
	var i uint16 = 0x1
	b := (*[2]byte)(unsafe.Pointer(&i))
	return b[0] == 0x1
}

// utility function to get the byte order based on system endianness
func GetOrder() binary.ByteOrder {
	var order binary.ByteOrder
	if IsLittleEndian() {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}
	return order
}

type Field interface {
	Name() string
	Align() int
	Size() int
	Serialize() ([]byte, error)
	Deserialize(buf []byte, offset int) (int, error)
}

// ------------------- Label Extraction -------------------

// here basically we can give mapName and aggregator and map_key path
type LabelConfig struct {
	Name string `json:"name"`
	Path string `json:"path"` // e.g., "Node.Children[0].ID"
}

// resolve path recursively
func ResolveFieldPath(root Field, path string) (Field, error) {
	parts := strings.Split(path, ".")
	current := root
	for _, p := range parts {
		idx := -1
		fieldName := p
		if strings.Contains(p, "[") && strings.HasSuffix(p, "]") {
			parts := strings.Split(p, "[")
			fieldName = parts[0]
			var err error
			idx, err = strconv.Atoi(strings.TrimSuffix(parts[1], "]"))
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", p)
			}
		}

		switch f := current.(type) {
		case *StructField:
			found := false
			for _, sf := range f.Fields {
				if sf.Name() == fieldName {
					current = sf
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("field %s not found", fieldName)
			}

		case *ArrayField:
			if idx < 0 || idx >= len(f.Elements) {
				return nil, fmt.Errorf("array index out of bounds: %d", idx)
			}
			current = f.Elements[idx]
		case *Uint8Field, *Uint32Field, *IPV4Field, *Uint16Field, *Uint64Field:
			return current, nil
		default:
			return nil, fmt.Errorf("cannot descend into non-struct/array field %s", f.Name())
		}
	}
	return current, nil
}

func ExtractLabelValuesWithConfig(key Field, labels []LabelConfig) (map[string]string, error) {
	values := make(map[string]string)
	for _, l := range labels {
		f, err := ResolveFieldPath(key, l.Path)
		if err != nil {
			return nil, err
		}
		switch v := f.(type) {
		case *Uint8Field:
			values[l.Name] = fmt.Sprintf("%d", v.Value)
		case *Uint32Field:
			values[l.Name] = fmt.Sprintf("%d", v.Value)
		case *Uint16Field:
			values[l.Name] = fmt.Sprintf("%d", v.Value)
		case *Uint64Field:
			values[l.Name] = fmt.Sprintf("%d", v.Value)
		case *IPV4Field:
			values[l.Name] = v.Value.String()
		case *ArrayField:
			if len(v.Elements) == 0 {
				values[l.Name] = ""
				continue
			}
			firstElem := v.Elements[0]
			switch firstElem.(type) {
			case *Uint8Field:
				var b []byte
				for _, elem := range v.Elements {
					b = append(b, elem.(*Uint8Field).Value)
				}

				values[l.Name] = string(b)
			case *Uint32Field:
				var parts []string
				for _, elem := range v.Elements {
					parts = append(parts, fmt.Sprintf("%d", elem.(*Uint32Field).Value))
				}
				values[l.Name] = strings.Join(parts, ",")
			default:
				values[l.Name] = "[array of struct]"
			}
		default:
			return nil, fmt.Errorf("unsupported label field type: %T", v)
		}
	}
	return values, nil
}

type FieldSchema struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Value  json.RawMessage `json:"value,omitempty"`
	Fields []FieldSchema   `json:"fields,omitempty"`
	Elem   *FieldSchema    `json:"elem,omitempty"`
	Length int             `json:"length,omitempty"`
}

func ParseSchema(schema FieldSchema) (Field, error) {
	switch schema.Type {
	case "uint8":
		var v uint8
		if schema.Value != nil {
			if err := json.Unmarshal(schema.Value, &v); err != nil {
				return nil, err
			}
		}
		return NewUint8Field(schema.Name, v), nil
	case "uint32":
		var v uint32
		if schema.Value != nil {
			if err := json.Unmarshal(schema.Value, &v); err != nil {
				return nil, err
			}
		}
		return NewUint32Field(schema.Name, v), nil
	case "uint16":
		var v uint16
		if schema.Value != nil {
			if err := json.Unmarshal(schema.Value, &v); err != nil {
				return nil, err
			}
		}
		return NewUint16Field(schema.Name, v), nil
	case "uint64":
		var v uint64
		if schema.Value != nil {
			if err := json.Unmarshal(schema.Value, &v); err != nil {
				return nil, err
			}
		}
		return NewUint64Field(schema.Name, v), nil
	case "ipv4":
		var v string
		if schema.Value != nil {
			if err := json.Unmarshal(schema.Value, &v); err != nil {
				return nil, err
			}
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", v)
			}
			return NewIPV4Field(schema.Name, ip), nil
		}
		return NewIPV4Field(schema.Name, nil), nil
	case "struct":
		fields := []Field{}
		for _, f := range schema.Fields {
			field, err := ParseSchema(f)
			if err != nil {
				return nil, err
			}
			fields = append(fields, field)
		}
		return NewStructField(schema.Name, fields), nil
	case "array":
		if schema.Elem == nil {
			return nil, fmt.Errorf("array must have elem schema")
		}
		elements := []Field{}
		if schema.Value != nil {
			var rawArr []json.RawMessage
			if err := json.Unmarshal(schema.Value, &rawArr); err != nil {
				return nil, err
			}
			for _, rv := range rawArr {
				elemSchema := *schema.Elem
				elemSchema.Value = rv
				elem, err := ParseSchema(elemSchema)
				if err != nil {
					return nil, err
				}
				elements = append(elements, elem)
			}
		} else {
			for i := 0; i < schema.Length; i++ {
				elem, _ := ParseSchema(*schema.Elem)
				elements = append(elements, elem)
			}
		}
		return NewArrayFieldFromElements(schema.Name, elements), nil
	default:
		return nil, fmt.Errorf("unknown type %s", schema.Type)
	}
}

func OpenPinnedMap(path string) (*ebpf.Map, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned map: %w", err)
	}
	return m, nil
}

func WriteToMap(m *ebpf.Map, key Field, value Field) error {
	kb, err := key.Serialize()
	if err != nil {
		return fmt.Errorf("serialize key: %w", err)
	}
	vb, err := value.Serialize()
	if err != nil {
		return fmt.Errorf("serialize value: %w", err)
	}
	if err := m.Put(kb, vb); err != nil {
		return fmt.Errorf("map put failed: %w", err)
	}
	return nil
}

func ReadFromMap(m *ebpf.Map, key Field, value Field) error {
	kb, err := key.Serialize()
	if err != nil {
		return fmt.Errorf("serialize key: %w", err)
	}
	vb := make([]byte, value.Size())
	if err := m.Lookup(kb, &vb); err != nil {
		return fmt.Errorf("map lookup failed: %w", err)
	}
	_, err = value.Deserialize(vb, 0)
	return err
}
