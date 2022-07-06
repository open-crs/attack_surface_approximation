/* Included libraries */

#include <dirent.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "QBDIPreload.h"
#include "utarray.h"

/* Constants and configuration */

#define MIN_MAPPED_ADDRESS 0xf0000000
#define BLOCKS_USED_IN_HASH 10000
#define MAX_ARGS_LENGTH 100
#define OUTPUT_FOLDER "traces/"

/* Structures */

typedef struct {
    unsigned int start;
    unsigned int end;
} segment;

typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;

/* Global variables, used to retain state between callbacks */

size_t segments_count = 0;
segment *segments = NULL;
UT_array *blocks;
char command_line[MAX_ARGS_LENGTH] = {'\0'};
char fds_location[20] = {'\0'};
pid_t pid;
char start_trace = 0, uses_canaries = 0;

QBDIPRELOAD_INIT;

unsigned long hash(char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

char *bin2hex(const unsigned char *data, size_t length) {
    char *out;
    size_t i;

    if (data == NULL || length == 0)
        return NULL;

    out = malloc(2 * length + 1);
    for (i = 0; i < length; i++) {
        out[i * 2] = "0123456789ABCDEF"[data[i] >> 4];
        out[i * 2 + 1] = "0123456789ABCDEF"[data[i] & 0x0F];
    }
    out[2 * length] = '\0';

    return out;
}

char *encode_command_line(const unsigned char *command, size_t length) {
    if (command == NULL || length == 0)
        return "none";

    return bin2hex(command, length);
}

static VMAction show_basic_block_callback(VMInstanceRef vm, const VMState* vmState, GPRState* gprState, FPRState* fprState, void* data) {
    size_t start_address, end_address;
    int abstract_address;
    char parent_segment = -1, i;

    // Check if the program reached main
    if (!start_trace) return QBDI_CONTINUE;

    // Get the absolute addresses
    start_address = vmState->basicBlockStart;
    end_address = vmState->basicBlockEnd;

    // If the end address is in the mapped memory zone, then continue
    if (end_address >= MIN_MAPPED_ADDRESS)
        return QBDI_CONTINUE;

    // Find the parent segment
    for (i = 0; i < segments_count; i++) {
        if (start_address >= segments[i].start && end_address <= segments[i].end) {
            parent_segment = i;
            break;
        }
    }

    // Compute the abstract address
    start_address -= segments[parent_segment].start;
    abstract_address = (parent_segment << 24) + start_address;
    utarray_push_back(blocks, &abstract_address);

    return QBDI_CONTINUE;
}

static VMAction transfer_execution_callback(VMInstanceRef vm, const VMState *vmState, GPRState *gprState, FPRState *fprState, void *data) {
    Dl_info info = {0};
    DIR *directory;
    struct dirent *directory_entry;
    char current_fd[256 + 20 + 10];
    char symlink_location[1024];
    unsigned int len;

    // Get the context
    dladdr((void *)gprState->eip, &info);

    // Check if the current call is to close
    if (info.dli_sname != NULL && strstr(info.dli_sname, "close") != NULL) {
        directory = opendir(fds_location);
        if (directory) {
            while ((directory_entry = readdir(directory)) != NULL) {
                sprintf(current_fd, "/proc/%d/fd/%s", pid, directory_entry->d_name);

                if ((len = readlink(current_fd, symlink_location, sizeof(symlink_location)-1)) != -1) {
                    if (strstr(symlink_location, ".opencrs") != NULL)
                        uses_canaries = 1;
                }

                memset(current_fd, '\0', sizeof(current_fd));
                memset(symlink_location, '\0', sizeof(symlink_location));
            }

            closedir(directory);
        }
    }

    return QBDI_CONTINUE;
}

int qbdipreload_on_start(void *main) {
    // Get the PID of the process
    pid = getpid();

    // Save the location of the opened file descriptors
    sprintf(fds_location, "/proc/%d/fd", pid);

    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_premain(void *gprCtx, void *fpuCtx) {
    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_main(int argc, char **argv) {
    int i;

    if (getenv("QBDI_DEBUG") != NULL) {
        qbdi_setLogPriority(QBDI_DEBUG);
    }
    else {
        qbdi_setLogPriority(QBDI_WARNING);
    }

    // Start the tracing
    start_trace = 1;

    // Copy the arguments
    for (i = 1; i < argc; i++) {
        strcat(command_line, argv[i]);
        strcat(command_line, " ");
    }

    return QBDIPRELOAD_NOT_HANDLED;
}

void get_segments() {
    qbdi_MemoryMap *maps;
    size_t maps_count;
    int i;

    // Get the memory maps
    maps = qbdi_getCurrentProcessMaps(false, &maps_count);

    // Get the number of executable segments
    for (i = 0; i < maps_count; i++) {
        if (maps[i].permission >= QBDI_PF_EXEC && maps[i].end < MIN_MAPPED_ADDRESS) {
            segments_count++;
        }
    }

    // Allocates the segments
    segments = (segment *)malloc(segments_count * sizeof(segment));

    // Store the segments
    for (i = 0; i < maps_count; i++) {
        if (maps[i].permission >= QBDI_PF_EXEC && maps[i].end < MIN_MAPPED_ADDRESS) {
            segments[i].start = maps[i].start;
            segments[i].end = maps[i].end;
        }
    }
}

int qbdipreload_on_run(VMInstanceRef vm, rword start, rword stop) {
    // Add a callback for basic block entry
    qbdi_addVMEventCB(vm, QBDI_BASIC_BLOCK_ENTRY, show_basic_block_callback, NULL);
    qbdi_addVMEventCB(vm, QBDI_EXEC_TRANSFER_CALL, transfer_execution_callback, NULL);

    // Get the segments and initialize the blocks array
    get_segments();
    utarray_new(blocks, &ut_int_icd);

    // Continue the execution
    qbdi_run(vm, start, stop);

    return QBDIPRELOAD_NO_ERROR;
}

int qbdipreload_on_exit(int status) {
    FILE *output_file;
    char hashed[2 * BLOCKS_USED_IN_HASH * sizeof(int)] = {'\0'};
    char current_hash[2 * sizeof(int)];
    char output_filename[2 * MAX_ARGS_LENGTH + sizeof(OUTPUT_FOLDER) + 1] = {'\0'};
    int *p;
    int i = 0;
    char uses_canaries_str;

    // Create the string to be hashed
    for (p = (int*)utarray_front(blocks); p != NULL && i < BLOCKS_USED_IN_HASH; p = (int*)utarray_next(blocks, p), i++) {
        sprintf(current_hash, "%x", *p);
        strcat(hashed, current_hash);
    }

    // Output to file
    strcat(output_filename, OUTPUT_FOLDER);
    strcat(output_filename, encode_command_line(command_line, strlen(command_line)));
    output_file = fopen(output_filename, "w");
    fprintf(output_file, "%d %ld %d", utarray_len(blocks), hash(hashed), uses_canaries);

    return QBDIPRELOAD_NO_ERROR;
}