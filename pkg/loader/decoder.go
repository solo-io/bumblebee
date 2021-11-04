package loader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

type BinaryDecoder interface {
	TranslateRawBuffer(
		ctx context.Context, typ *btf.Struct,
	) error
}

func NewDecoder(raw []byte) BinaryDecoder {
	return &decoder{
		raw: raw,
	}
}

type decoder struct {
	// Offset within the buffer from which we are currently reading
	offset uint32
	// Raw binary bytes to read from
	raw []byte
}

func (d *decoder) TranslateRawBuffer(
	ctx context.Context, typ *btf.Struct,
) error {
	// Parse the ringbuf event entry into an Event structure.
	// buf := bytes.NewBuffer(raw)
	for _, member := range typ.Members {
		_, err := d.processSingleType(member.Type)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) processSingleType(typ btf.Type) (interface{}, error) {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			// Default encoding seems to be unsigned
			fmt.Println(typedMember.Bits)
			fmt.Println(typedMember.Size)
			buf := bytes.NewBuffer(d.raw[d.offset : d.offset+typedMember.Size])
			d.offset += typedMember.Size
			switch typedMember.Bits {
			case 64:
				var val int64
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 32:
				var val int32
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 16:
				var val int16
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 8:
				var val int8
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			}
			return nil, errors.New("this should never happen")
		case btf.Bool:
			// TODO
			return false, nil
		case btf.Char:
			// TODO
			return "", nil
		default:
			// Default encoding seems to be unsigned
			buf := bytes.NewBuffer(d.raw[d.offset : d.offset+typedMember.Size])
			d.offset += typedMember.Size
			switch typedMember.Bits {
			case 64:
				var val uint64
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 32:
				var val uint32
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 16:
				var val uint16
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 8:
				var val uint8
				if err := binary.Read(buf, Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			}
			return nil, errors.New("this should never happen")
		}
	case *btf.Typedef:
		underlying, err := getUnderlyingType(typedMember)
		if err != nil {
			return nil, err
		}
		return d.processSingleType(underlying)
	case *btf.Float:
		return float64(0), nil
	default:
		return nil, errors.New("only primitive types allowed")
	}
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}
