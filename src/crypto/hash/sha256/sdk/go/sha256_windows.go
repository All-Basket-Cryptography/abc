// Package abc exposes the ABC research SHA-256 provider through its C ABI.
package abc

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const digestBytes = 32

// Provider identifies the loaded native implementation and provides new hashes.
type Provider struct {
	library                  *syscall.DLL
	implementation           string
	digest, newState, update *syscall.Proc
	finish, reset, free      *syscall.Proc
}

// Open loads a caller-provided, absolute path to the packaged Windows DLL.
// The DLL remains loaded for the lifetime of the process.
func Open(path string) (*Provider, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("ABC requires an absolute DLL path")
	}
	library, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("load ABC DLL: %w", err)
	}
	names := []string{"abc_abi_version", "abc_sha256_implementation", "abc_sha256_digest", "abc_sha256_new", "abc_sha256_update", "abc_sha256_finalize", "abc_sha256_reset", "abc_sha256_free"}
	procedures := make([]*syscall.Proc, 0, len(names))
	for _, name := range names {
		proc, err := library.FindProc(name)
		if err != nil {
			_ = library.Release()
			return nil, fmt.Errorf("resolve %s: %w", name, err)
		}
		procedures = append(procedures, proc)
	}
	if version, _, _ := procedures[0].Call(); version != 0x00010000 {
		_ = library.Release()
		return nil, fmt.Errorf("unsupported ABC ABI version %d", version)
	}
	address, _, _ := procedures[1].Call()
	identity, err := readIdentity(address)
	if err != nil {
		_ = library.Release()
		return nil, err
	}
	return &Provider{library, identity, procedures[2], procedures[3], procedures[4], procedures[5], procedures[6], procedures[7]}, nil
}

func readIdentity(address uintptr) (string, error) {
	if address == 0 {
		return "", errors.New("ABC returned a null implementation identity")
	}
	// Read the C string using the OS so integer pointer provenance stays outside Go.
	readMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("ReadProcessMemory")
	var identity [128]byte
	for index := range identity {
		result, _, callErr := readMemory.Call(^uintptr(0), address+uintptr(index), uintptr(unsafe.Pointer(&identity[index])), 1, 0)
		if result == 0 {
			return "", fmt.Errorf("read ABC implementation identity: %w", callErr)
		}
		if identity[index] == 0 && index > 0 {
			return string(identity[:index]), nil
		}
		if identity[index] == 0 {
			break
		}
	}
	return "", errors.New("Invalid ABC implementation identity")
}

// Implementation reports the C ABI's implementation identifier.
func (provider *Provider) Implementation() string { return provider.implementation }

func check(code uintptr) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("ABC SHA-256 native status %d", int32(code))
}

func (provider *Provider) Digest(input []byte) ([digestBytes]byte, error) {
	var output [digestBytes]byte
	code, _, _ := provider.digest.Call(uintptr(unsafe.Pointer(unsafe.SliceData(input))), uintptr(len(input)), uintptr(unsafe.Pointer(&output[0])), digestBytes)
	runtime.KeepAlive(input)
	return output, check(code)
}

// Stream owns one native context. Close releases it.
type Stream struct {
	mu       sync.Mutex
	provider *Provider
	handle   uintptr
}

func (provider *Provider) NewStream() (*Stream, error) {
	var handle uintptr
	code, _, _ := provider.newState.Call(uintptr(unsafe.Pointer(&handle)))
	if err := check(code); err != nil {
		return nil, err
	}
	if handle == 0 {
		return nil, errors.New("ABC allocated a null hash context")
	}
	return &Stream{provider: provider, handle: handle}, nil
}

func (stream *Stream) Update(input []byte) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.handle == 0 {
		return errors.New("ABC SHA-256 stream is closed")
	}
	code, _, _ := stream.provider.update.Call(stream.handle, uintptr(unsafe.Pointer(unsafe.SliceData(input))), uintptr(len(input)))
	runtime.KeepAlive(input)
	return check(code)
}

func (stream *Stream) Finalize() ([digestBytes]byte, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	var output [digestBytes]byte
	if stream.handle == 0 {
		return output, errors.New("ABC SHA-256 stream is closed")
	}
	code, _, _ := stream.provider.finish.Call(stream.handle, uintptr(unsafe.Pointer(&output[0])), digestBytes)
	return output, check(code)
}

func (stream *Stream) Reset() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.handle == 0 {
		return errors.New("ABC SHA-256 stream is closed")
	}
	code, _, _ := stream.provider.reset.Call(stream.handle)
	return check(code)
}

func (stream *Stream) Close() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.handle == 0 {
		return nil
	}
	stream.provider.free.Call(stream.handle)
	stream.handle = 0
	return nil
}
