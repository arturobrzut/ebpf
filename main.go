package main

import "C"

import (
	"bufio"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"os"
	"time"
	"unsafe"
)

func main() {
	fmt.Println("CONFIG: Filename: " + os.Getenv("FILE_CHECK") + ", DEBUG=" + os.Getenv("DEBUG"))
	if os.Getenv("DEBUG") == "1" {
		go kernelTrace()
	}

	// LOAD BPF OBJECT AND GET MAP
	bpfModule, err := LoadBPF("/home/main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	// GET KERNEL MAP
	techTalkMap, err := bpfModule.GetMap("tech_talk")
	if err != nil {
		bpfModule.Close()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// READ FILENAME FROM CONFIG MAP
	filenameCheck := []byte(os.Getenv("FILE_CHECK"))

	// ADD FILENAME TO KERNEL MAP AS OUR EBPF CONFIGURATION
	inputKeyId := uint32(1)
	inputKeyIdUS := unsafe.Pointer(&inputKeyId)
	inputValueUS := unsafe.Pointer(&filenameCheck[0])
	clearMapData(techTalkMap)
	techTalkMap.Update(inputKeyIdUS, inputValueUS)

	// GET OUR PROGRAM AND ATTACH IT TO THE CHMOD HOOK (CHANGE PERMISSION) -> START EBPF
	program, err := bpfModule.GetProgram("hello_tech_talk")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	_, err = program.AttachTracepoint("syscalls", "sys_enter_fchmodat")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	fmt.Println("Waiting for data")
	for {
		// GET VALUE FROM KERNEL MAP
		outputKeyId := uint32(2)
		outputKeyIdUS := unsafe.Pointer(&outputKeyId)
		dataFromKernel, err := techTalkMap.GetValue(outputKeyIdUS)
		if err != nil {
			fmt.Println("ERROR ")
			fmt.Fprintln(os.Stderr, err)
		}
		if dataFromKernelSend(dataFromKernel) {
			fmt.Println("DETECT CHMOD ON MY FILE: " + string(filenameCheck))
		}
		// AFTER READ CLEAR DATA IN MAP
		clearMapData(techTalkMap)
		time.Sleep(3 * time.Second)
	}
}

func LoadBPF(filename string) (*bpf.Module, error) {
	bpfModule, err := bpf.NewModuleFromFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		bpfModule.Close()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return bpfModule, err
}

func clearMapData(bpfMap *bpf.BPFMap) {
	empty := []byte(" ")
	inputUS := unsafe.Pointer(&empty[0])
	outputKeyId := uint32(2)
	outputKeyIdUS := unsafe.Pointer(&outputKeyId)
	err := bpfMap.Update(outputKeyIdUS, inputUS)
	if err != nil {
		fmt.Println("ERROR in clear data from map")
		fmt.Fprintln(os.Stderr, err)
	}
}

func dataFromKernelSend(dataFromKernel []byte) bool {
	return dataFromKernel[0] != ' '
}
func kernelTrace() {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		fmt.Println("KERNEL: trace failed to open pipe: %v", err)
		return
	}
	r := bufio.NewReader(f)
	b := make([]byte, 1000)
	for {
		len, err := r.Read(b)
		if err != nil {
			fmt.Println("KERNEL: TracePrint failed to read from trace pipe: %v", err)
			return
		}
		s := string(b[:len])
		fmt.Println("KERNEL: " + s)
	}
}
