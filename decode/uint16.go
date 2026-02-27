package decode

type Uint16Field struct {
	name  string
	Value uint16
}

func (f *Uint16Field) Name() string { return f.name }
func (f *Uint16Field) Align() int   { return 2 }
func (f *Uint16Field) Size() int    { return 2 }
func NewUint16Field(name string, value uint16) *Uint16Field {
	return &Uint16Field{name: name, Value: value}
}
func (f *Uint16Field) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	GetOrder().PutUint16(buf, f.Value)
	return buf, nil
}

func (f *Uint16Field) Deserialize(buf []byte, offset int) (int, error) {
	f.Value = GetOrder().Uint16(buf[offset:])
	return offset + 2, nil
}
