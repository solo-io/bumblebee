package loader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/btf"
)

const (
	ipv4AddrTypeName = "ipv4_addr"
	ipv6AddrTypeName = "ipv6_addr"
	durationTypeName = "duration"
)

type BinaryDecoder interface {
	// DecodeBinaryStruct takes in a btf struct spec, and translates
	// raw binary data into a map[string]interface{} of that format.
	// If the incoming type is not a struct, it will return map[""]<type>
	DecodeBtfBinary(
		ctx context.Context, typ btf.Type, raw []byte,
	) (map[string]interface{}, error)
}

type DecoderFactory func() BinaryDecoder

func NewDecoderFactory() DecoderFactory {
	return newDecoder
}

func newDecoder() BinaryDecoder {
	return &decoder{}
}

type decoder struct {
	// Offset within the buffer from which we are currently reading
	offset uint32
	// Raw binary bytes to read from
	raw []byte
}

func (d *decoder) DecodeBtfBinary(
	ctx context.Context, typ btf.Type, raw []byte,
) (map[string]interface{}, error) {
	// Reset values when called
	d.raw = raw
	d.offset = 0

	switch typedBtf := typ.(type) {
	case *btf.Struct:
		// Parse the ringbuf event entry into an Event structure.
		// buf := bytes.NewBuffer(raw)
		result := make(map[string]interface{})
		for _, member := range typedBtf.Members {
			val, err := d.processSingleType(member.Type)
			if err != nil {
				return nil, err
			}
			result[member.Name] = val
		}
		return result, nil
	case *btf.Typedef:
		val, err := d.processSingleType(typedBtf)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"": val}, nil
	case *btf.Float:
		val, err := d.processSingleType(typedBtf)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"": val}, nil
	case *btf.Int:
		val, err := d.processSingleType(typedBtf)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"": val}, nil
	default:
		return nil, fmt.Errorf("unsupported type, %s", typedBtf.String())
	}
}

func (d *decoder) processSingleType(typ btf.Type) (interface{}, error) {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			return d.handleInt(typedMember)
		case btf.Bool:
			// TODO
			return false, nil
		case btf.Char:
			// TODO
			return "", nil
		default:
			// Default encoding seems to be unsigned
			return d.handleUint(typedMember)
		}
	case *btf.Typedef:
		// Handle special types
		underlying, err := getUnderlyingType(typedMember)
		if err != nil {
			return nil, err
		}
		processed, err := d.processSingleType(underlying)
		if err != nil {
			return nil, err
		}

		switch typedMember.Name {
		case durationTypeName:
			return u64ToDuration(processed)
		case ipv4AddrTypeName:
			return u32ToIp(processed)
		case ipv6AddrTypeName:
			return u32ToIp(processed)
		default:
			return processed, nil
		}

	case *btf.Float:
		return d.handleFloat(typedMember)
	default:
		return nil, errors.New("only primitive types allowed")
	}
}

func (d *decoder) handleFloat(
	typedMember *btf.Float,
) (interface{}, error) {
	buf := bytes.NewBuffer(d.raw[d.offset : d.offset+typedMember.Size])
	d.offset += typedMember.Size
	switch typedMember.Size {
	case 8:
		var val float64
		if err := binary.Read(buf, Endianess, &val); err != nil {
			return nil, err
		}
		return val, nil
	case 4:
		var val float32
		if err := binary.Read(buf, Endianess, &val); err != nil {
			return nil, err
		}
		return val, nil
	}
	return nil, errors.New("this should never happen")
}

func (d *decoder) handleUint(
	typedMember *btf.Int,
) (interface{}, error) {
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

func (d *decoder) handleInt(
	typedMember *btf.Int,
) (interface{}, error) {
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
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

// TODO: Process into string at a later time.
func u64ToDuration(val interface{}) (time.Duration, error) {
	u64Val, ok := val.(uint64)
	if !ok {
		return 0, errors.New("this should never happen")
	}
	// TODO: Check if overflow somehow
	return time.Duration(u64Val), nil
}

func u32ToIp(val interface{}) (net.IP, error) {
	u32Val, ok := val.(uint32)
	if !ok {
		return net.IP{}, errors.New("this should never happen")
	}
	ip := make(net.IP, 4)
	Endianess.PutUint32(ip, u32Val)
	return ip, nil
}
