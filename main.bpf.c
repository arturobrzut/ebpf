#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct fchmodat_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    int mode;
    char *filename;
    int mode2;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, char[64]);
    __uint(max_entries, 64);
} dod SEC(".maps");

int compare(char src[64], char dst[64], int sizeVal) {
  int retVal = 0;
  for (int index=0;index<sizeVal;index++) {
      if (src[index] != dst[index]) {
        retVal = 1;
        break;
      }
  }
  return retVal;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int hello_dod(struct fchmodat_args *ctx)
{
    int ret;
    u32 inputKey = 1;
    u32 keyOutput = 2;
    char valMyFileName[64];
    char valKernelFileName[64];
    char sendOK[64];
    char *tmpData;
    char *tmpData2;
    
    // get filename from event -> someone open the file
    ret = bpf_probe_read(&tmpData, sizeof(tmpData), &ctx->filename);
    if (ret != 0) {
        bpf_printk("ERROR Read");
    }
    bpf_probe_read_str(valKernelFileName, sizeof(valKernelFileName), tmpData);

    // get filename from eBPFMap -> our configuration
    char *filename = bpf_map_lookup_elem(&dod,&inputKey);
    if (!filename) {
        bpf_printk("ERROR Read problem with configmap");
    }
    ret = bpf_probe_read(&tmpData2, sizeof(tmpData2), &filename);
    if (ret != 0) {
        bpf_printk("ERROR Read");
    }
    bpf_probe_read_str(valMyFileName, sizeof(valMyFileName), tmpData2);
    
    // Compare filename from eBPFMap and from the event
    if (compare(valKernelFileName, valMyFileName, 11) == 0) {
        
        // If this is the same filename 
        // update eBPFMap for UserSpace Program -> notification
        ret = bpf_map_update_elem(&dod, &keyOutput, &valMyFileName, BPF_ANY);
        if (ret != 0) {
            bpf_printk("ERROR during map update");
        }
        bpf_printk("Found unauthorized open my file, kill the process");
        bpf_printk("FileName: %s ",valKernelFileName);
        bpf_printk("PID: %d",bpf_get_current_pid_tgid());
        //And Kill the process who Open the file 
        bpf_send_signal(9);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
