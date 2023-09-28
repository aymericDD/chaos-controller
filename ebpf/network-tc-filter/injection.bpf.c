// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.

// +build ignore
#include "injection.bpf.h"

#define MAX_PATH_LEN 20
#define MAX_METHOD_LEN 8
#define MAX_ENTRIES 5 // Define the maximum number of method-path pairs

// Define a struct to hold a list of paths for an HTTP method
struct method_paths {
    char paths[MAX_ENTRIES][MAX_PATH_LEN];
};

// Define the eBPF map to store the method-paths pairs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, char[MAX_METHOD_LEN]);
    __type(value, struct method_paths);
} config_map SEC(".maps");

static __always_inline bool  validate_request(char* current_path, char* method) {
     struct method_paths pair;

     char key2[MAX_METHOD_LEN] = "GET";
//     char key[MAX_METHOD_LEN];
//     bpf_probe_read_kernel_str(&key, sizeof(key), method);

     char key[MAX_METHOD_LEN];

     // Ensure the destination array is null-terminated
     key[MAX_METHOD_LEN - 1] = '\0';

     for (int i = 0; i < MAX_METHOD_LEN - 1; i++) {
        key[i] = method[i];
        if (method[i] == '\0') {
            break; // Stop copying when the null terminator is reached
        }
     }

     for (int i = 0; i < MAX_METHOD_LEN ; i++) {
        printt("key-%d: %d", i, key[i]);
        printt("key2-%d: %d", i, key2[i]);
        printt("METHOD-%d: %d", i, method[i]);

     }

     printt("METHOD: %s", key);

     bpf_probe_read_kernel(&pair, sizeof(pair), bpf_map_lookup_elem(&config_map, &key));

     char paths[MAX_ENTRIES][MAX_PATH_LEN];
     bpf_probe_read_kernel(&paths, sizeof(paths), &pair.paths);

     int paths_len = 0;
     paths_len = (int) (sizeof(paths) / sizeof(paths[0])) - 1;

     if (paths_len == 0) {
        return false;
     }

     // Get the path of the response.
     char request_path[MAX_PATH_LEN];
     bpf_probe_read_kernel_str(&request_path, sizeof(request_path), current_path);

     printt("request_path: %s", request_path);

     // Iterate through the stored paths and check for a match
     for (int i = 0; i < MAX_ENTRIES ; i++) {
        char path[MAX_PATH_LEN];
        bpf_probe_read_kernel_str(&path, sizeof(path),  paths[i]);

        printt("path-%d: %s", i, path);
        if (path[0] == 0) {
            continue;
        }

        if (has_prefix(request_path, path)) {
            return true;
        }
     }

     return false;
}

SEC("classifier")
int cls_entry(struct __sk_buff *skb)
{
    skb_info_t skb_info;

    if (!read_conn_tuple_skb(skb, &skb_info))
        return 0;

    char p[HTTP_BUFFER_SIZE];
    http_packet_t packet_type;

    if (skb->len - skb_info.data_off < HTTP_BUFFER_SIZE) {
        printt("http buffer reach the limit");
        return 0;
    }

    for (int i = 0; i < HTTP_BUFFER_SIZE; i++) {
        p[i] = load_byte(skb, skb_info.data_off + i);
    }

    char *method = get_method(p);
    if (method == "UNKNOWN") {
       printt("not an http request");
       return 0;
    }

    int i;
    char path[MAX_PATH_LEN];
    int path_length = 0;

    // Extract the path from the response
    for (i = 0; i < HTTP_BUFFER_SIZE; i++) {
        if (p[i] == ' ') {
            i++;
            // Find the end of the path
            while (i < HTTP_BUFFER_SIZE && p[i] != ' ' && path_length < MAX_PATH_LEN - 1) {
                path[path_length] = p[i];
                path_length++;
                i++;
            }

            // Null-terminate the path
            path[path_length] = '\0';
            break;
        }
    }

    printt("PATH: %s", path);

    if (validate_request(path, method)) {
        printt("DISRUPTED PATH %s", path);
        return -1;
    }

    // Don't apply the next tc rule.
    return 0;
}
