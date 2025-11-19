package decode

type Uint32Field struct {
	name  string
	Value uint32
}

func (f *Uint32Field) Name() string { return f.name }
func (f *Uint32Field) Align() int   { return 4 }
func (f *Uint32Field) Size() int    { return 4 }
func NewUint32Field(name string, value uint32) *Uint32Field {
	return &Uint32Field{name: name, Value: value}
}
func (f *Uint32Field) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	GetOrder().PutUint32(buf, f.Value)
	return buf, nil
}

func (f *Uint32Field) Deserialize(buf []byte, offset int) (int, error) {
	f.Value = GetOrder().Uint32(buf[offset:])
	return offset + 4, nil
}
