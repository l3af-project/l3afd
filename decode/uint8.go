package decode

type Uint8Field struct {
	name  string
	Value uint8
}

func (f *Uint8Field) Name() string { return f.name }
func (f *Uint8Field) Align() int   { return 1 }
func (f *Uint8Field) Size() int    { return 1 }
func NewUint8Field(name string, value uint8) *Uint8Field {
	return &Uint8Field{name: name, Value: value}
}

func (f *Uint8Field) Serialize() ([]byte, error) {
	return []byte{f.Value}, nil
}

func (f *Uint8Field) Deserialize(buf []byte, offset int) (int, error) {
	f.Value = buf[offset]
	return offset + 1, nil
}
