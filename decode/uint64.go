package decode

type Uint64Field struct {
	name  string
	Value uint64
}

func (f *Uint64Field) Name() string { return f.name }
func (f *Uint64Field) Align() int   { return 8 }
func (f *Uint64Field) Size() int    { return 8 }
func NewUint64Field(name string, value uint64) *Uint64Field {
	return &Uint64Field{name: name, Value: value}
}
func (f *Uint64Field) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	GetOrder().PutUint64(buf, f.Value)
	return buf, nil
}

func (f *Uint64Field) Deserialize(buf []byte, offset int) (int, error) {
	f.Value = GetOrder().Uint64(buf[offset:])
	return offset + 8, nil
}
