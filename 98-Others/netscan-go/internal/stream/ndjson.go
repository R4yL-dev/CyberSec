// Package stream carries the domain-A transport: newline-delimited JSON
// (NDJSON) records over stdin/stdout, so `ns-discover | ns-ingest` (or a file
// in between) composes as a Unix pipeline.
package stream

import (
	"bufio"
	"encoding/json"
	"io"

	"netscan/internal/model"
)

// Encoder writes WireRecords as NDJSON (one JSON object per line).
type Encoder struct {
	bw  *bufio.Writer
	enc *json.Encoder
}

// NewEncoder buffers writes to w; call Flush before exit.
func NewEncoder(w io.Writer) *Encoder {
	bw := bufio.NewWriter(w)
	return &Encoder{bw: bw, enc: json.NewEncoder(bw)}
}

// Encode writes one record followed by a newline.
func (e *Encoder) Encode(r model.WireRecord) error { return e.enc.Encode(r) }

// Flush pushes any buffered output to the underlying writer.
func (e *Encoder) Flush() error { return e.bw.Flush() }

// Decode reads NDJSON WireRecords from r, invoking fn for each one. It returns
// nil at end of input, or the first error from decoding or fn.
func Decode(r io.Reader, fn func(model.WireRecord) error) error {
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var rec model.WireRecord
		err := dec.Decode(&rec)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}
