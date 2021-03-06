pub const BPF_MAP_TYPE_UNSPEC: bpf_map_type = 0;
pub const BPF_MAP_TYPE_HASH: bpf_map_type = 1;
pub const BPF_MAP_TYPE_ARRAY: bpf_map_type = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: bpf_map_type = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: bpf_map_type = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH: bpf_map_type = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: bpf_map_type = 6;
pub const BPF_MAP_TYPE_STACK_TRACE: bpf_map_type = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY: bpf_map_type = 8;
pub const BPF_MAP_TYPE_LRU_HASH: bpf_map_type = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: bpf_map_type = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: bpf_map_type = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: bpf_map_type = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS: bpf_map_type = 13;
pub const BPF_MAP_TYPE_DEVMAP: bpf_map_type = 14;
pub const BPF_MAP_TYPE_SOCKMAP: bpf_map_type = 15;
pub const BPF_MAP_TYPE_CPUMAP: bpf_map_type = 16;
pub const BPF_MAP_TYPE_XSKMAP: bpf_map_type = 17;
pub const BPF_MAP_TYPE_SOCKHASH: bpf_map_type = 18;
pub const BPF_MAP_TYPE_CGROUP_STORAGE: bpf_map_type = 19;
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: bpf_map_type = 20;
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: bpf_map_type = 21;
pub const BPF_MAP_TYPE_QUEUE: bpf_map_type = 22;
pub const BPF_MAP_TYPE_STACK: bpf_map_type = 23;
pub const BPF_MAP_TYPE_SK_STORAGE: bpf_map_type = 24;
pub const BPF_MAP_TYPE_DEVMAP_HASH: bpf_map_type = 25;
pub type bpf_map_type = u32;
