package rewriter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// orderedMap is a thin JSON-aware ordered map. We deliberately do not pull
// a third-party dep — it's about 80 lines and we don't need cycle handling
// or schema awareness, just preservation of key order.
//
// Values are stored as `any` and may be:
//   - *orderedMap (nested object)
//   - []any       (array)
//   - string / float64 / bool / nil (JSON primitives)
//
// On marshal we walk the structure and emit canonical JSON with stable
// key order matching insertion (or rather, last-set) order.
type orderedMap struct {
	keys   []string
	values map[string]any
}

func newOrderedMap() *orderedMap {
	return &orderedMap{values: map[string]any{}}
}

// parseOrdered consumes raw JSON into orderedMaps preserving object key
// order. It tolerates any valid JSON document whose root is an object.
func parseOrdered(raw []byte) (*orderedMap, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("ordered: root is not an object")
	}
	return parseObject(dec)
}

func parseObject(dec *json.Decoder) (*orderedMap, error) {
	m := newOrderedMap()
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("ordered: expected string key, got %T", keyTok)
		}
		val, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		m.set(key, val)
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return m, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			return parseObject(dec)
		case '[':
			return parseArray(dec)
		}
	}
	return tok, nil
}

func parseArray(dec *json.Decoder) ([]any, error) {
	var out []any
	for dec.More() {
		v, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := dec.Token(); err != nil { // ']'
		return nil, err
	}
	return out, nil
}

func (m *orderedMap) set(key string, val any) {
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = val
}

func (m *orderedMap) delete(key string) {
	if _, ok := m.values[key]; !ok {
		return
	}
	delete(m.values, key)
	for i, k := range m.keys {
		if k == key {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			return
		}
	}
}

func (m *orderedMap) empty() bool {
	return len(m.keys) == 0
}

func (m *orderedMap) getMap(key string) (*orderedMap, bool) {
	v, ok := m.values[key]
	if !ok {
		return nil, false
	}
	om, ok := v.(*orderedMap)
	return om, ok
}

func (m *orderedMap) getString(key string) (string, bool) {
	v, ok := m.values[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (m *orderedMap) getStringArray(key string) []string {
	v, ok := m.values[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (m *orderedMap) marshalIndent(prefix, indent string) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, m, prefix, indent, 0); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any, prefix, indent string, depth int) error {
	switch x := v.(type) {
	case *orderedMap:
		return writeMap(buf, x, prefix, indent, depth)
	case []any:
		return writeArray(buf, x, prefix, indent, depth)
	case []string:
		// Convenience: rewriter sets args as []string.
		arr := make([]any, len(x))
		for i, s := range x {
			arr[i] = s
		}
		return writeArray(buf, arr, prefix, indent, depth)
	default:
		// Primitives — use stdlib for correctness.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil
	}
}

func writeMap(buf *bytes.Buffer, m *orderedMap, prefix, indent string, depth int) error {
	if m == nil || len(m.keys) == 0 {
		buf.WriteString("{}")
		return nil
	}
	buf.WriteByte('{')
	pad := prefix
	for i := 0; i <= depth; i++ {
		pad += indent
	}
	closePad := prefix
	for i := 0; i < depth; i++ {
		closePad += indent
	}
	for i, k := range m.keys {
		buf.WriteByte('\n')
		buf.WriteString(pad)
		key, _ := json.Marshal(k)
		buf.Write(key)
		buf.WriteString(": ")
		if err := writeValue(buf, m.values[k], prefix, indent, depth+1); err != nil {
			return err
		}
		if i < len(m.keys)-1 {
			buf.WriteByte(',')
		}
	}
	buf.WriteByte('\n')
	buf.WriteString(closePad)
	buf.WriteByte('}')
	return nil
}

func writeArray(buf *bytes.Buffer, arr []any, prefix, indent string, depth int) error {
	if len(arr) == 0 {
		buf.WriteString("[]")
		return nil
	}
	buf.WriteByte('[')
	pad := prefix
	for i := 0; i <= depth; i++ {
		pad += indent
	}
	closePad := prefix
	for i := 0; i < depth; i++ {
		closePad += indent
	}
	for i, v := range arr {
		buf.WriteByte('\n')
		buf.WriteString(pad)
		if err := writeValue(buf, v, prefix, indent, depth+1); err != nil {
			return err
		}
		if i < len(arr)-1 {
			buf.WriteByte(',')
		}
	}
	buf.WriteByte('\n')
	buf.WriteString(closePad)
	buf.WriteByte(']')
	return nil
}
