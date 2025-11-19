package decode

type StructField struct {
	name   string
	Fields []Field
}

func (s *StructField) Name() string { return s.name }

func NewStructField(name string, fields []Field) *StructField {
	if len(fields) == 0 {
		return nil
	}
	return &StructField{name: name, Fields: fields}
}

func (s *StructField) Align() int {
	max := 1
	for _, f := range s.Fields {
		if a := f.Align(); a > max {
			max = a
		}
	}
	return max
}

func (s *StructField) Size() int {
	size := 0
	for _, f := range s.Fields {
		size = align(size, f.Align())
		size += f.Size()
	}
	return align(size, s.Align())
}

func (s *StructField) Serialize() ([]byte, error) {
	buf := []byte{}
	for _, f := range s.Fields {
		buf = append(buf, make([]byte, align(len(buf), f.Align())-len(buf))...)
		b, err := f.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func (s *StructField) Deserialize(buf []byte, offset int) (int, error) {
	for _, f := range s.Fields {
		offset = align(offset, f.Align())
		next, err := f.Deserialize(buf, offset)
		if err != nil {
			return offset, err
		}
		offset = next
	}
	return offset, nil
}
