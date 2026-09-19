package decode

type ArrayField struct {
	name        string
	elemFactory func() Field
	Elements    []Field
	Length      int
}

func NewArrayField(name string, length int, elemFactory func() Field) *ArrayField {
	a := &ArrayField{
		name:        name,
		elemFactory: elemFactory,
		Length:      length,
	}
	a.Elements = make([]Field, length)
	for i := 0; i < length; i++ {
		a.Elements[i] = elemFactory()
	}
	return a
}

func NewArrayFieldFromElements(name string, elements []Field) *ArrayField {
	return &ArrayField{
		name:     name,
		Elements: elements,
		Length:   len(elements),
	}
}

func (a *ArrayField) Name() string { return a.name }

func (a *ArrayField) Align() int {
	if a.Length == 0 {
		return 1
	}
	return a.Elements[0].Align()
}

func (a *ArrayField) Size() int {
	if a.Length == 0 {
		return 0
	}
	return a.Elements[0].Size() * a.Length
}

func (a *ArrayField) Serialize() ([]byte, error) {
	buf := []byte{}
	for _, elem := range a.Elements {
		buf = append(buf, make([]byte, align(len(buf), elem.Align())-len(buf))...)
		b, err := elem.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func (a *ArrayField) Deserialize(buf []byte, offset int) (int, error) {
	if a.Elements == nil || len(a.Elements) != a.Length {
		a.Elements = make([]Field, a.Length)
		for i := 0; i < a.Length; i++ {
			a.Elements[i] = a.elemFactory()
		}
	}

	for i := 0; i < a.Length; i++ {
		elem := a.Elements[i]
		offset = align(offset, elem.Align())
		next, err := elem.Deserialize(buf, offset)
		if err != nil {
			return offset, err
		}
		offset = next
	}
	return offset, nil
}
