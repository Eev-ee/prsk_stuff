#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define ASSERT(condition, msg, ...)             \
    do {                                        \
        if (!(condition)) {                     \
            fprintf(stderr, msg, ##__VA_ARGS__);\
            goto error_exit;                    \
        }                                       \
    } while (0)

long int find_key_start_idx(unsigned char *libil2cpp_buffer, long int libil2cpp_size, unsigned char known_key[4]) {
    long int key_start_idx = -1;
    for (long int i = 0; i < libil2cpp_size - libil2cpp_size % 4; i++) { // So that the inner loop doesn't overflow
        int not_found = 0;
        for (int j = 0; j < 4; j++) {
            if (libil2cpp_buffer[i + j] != known_key[j]) {
                not_found = 1;
                break;
            }
        }
        if (!not_found) {
            key_start_idx = i;
            break;
        }
    }
    return key_start_idx;
}

void decrypt(unsigned char *encrypted, unsigned char *key, unsigned int size, unsigned int key_length) {
    for (unsigned int i = 0; i < size; i++) {
        encrypted[i] ^= key[i % key_length];
    }
}

int main(int argc, char **argv) {
    FILE *encrypted_metadata = NULL, *libil2cpp = NULL, *decrypted_metadata = NULL;
    long int metadata_size, libil2cpp_size, key_start_idx;
    unsigned char *metadata_buffer = NULL, *libil2cpp_buffer = NULL;
    unsigned int key_len;


    //Arguments check
    ASSERT(argc == 4, "3 arguments were expected! main.exe <path_to_global-metadata.dat> <path_to_libil2cpp.so> <path_to_decrypted-global-metadata.dat>");

    //File check
    printf("Opening %s ...\n", argv[1]);
    encrypted_metadata = fopen(argv[1], "rb");
    ASSERT(encrypted_metadata, "Failed to open %s !!!", argv[1]);
    printf("Opening %s ...\n", argv[2]);
    libil2cpp = fopen(argv[2], "rb");
    ASSERT(libil2cpp, "Failed to open %s !!!", argv[2]);
    printf("Opening %s ...\n", argv[3]);
    decrypted_metadata = fopen(argv[3], "wb");
    ASSERT(decrypted_metadata, "Failed to open %s !!!", argv[3]);

    //Find the file size
    fseek(encrypted_metadata, 0, SEEK_END);
    metadata_size = ftell(encrypted_metadata);
    rewind(encrypted_metadata);

    fseek(libil2cpp, 0, SEEK_END);
    libil2cpp_size = ftell(libil2cpp);
    rewind(libil2cpp);

    //Create buffer
    metadata_buffer = malloc(metadata_size);
    libil2cpp_buffer = malloc(libil2cpp_size);
    ASSERT(metadata_buffer && libil2cpp_buffer, "Failed to allocate memory!");

    fread(metadata_buffer, 1, metadata_size, encrypted_metadata);
    fread(libil2cpp_buffer, 1, libil2cpp_size, libil2cpp);

    ////https://github.com/MlgmXyysd/libil2cpp/blob/master/libil2cpp/Unity_2022.3/2022.3.9f1/vm/GlobalMetadata.cpp#L331
    unsigned char known_key[4] = {metadata_buffer[0] ^ 0xAF, metadata_buffer[1] ^ 0x1B, metadata_buffer[2] ^ 0xB1, metadata_buffer[3] ^ 0xFA};
    key_start_idx = find_key_start_idx(libil2cpp_buffer, libil2cpp_size, known_key);
    ASSERT(key_start_idx != -1, "Failed to find the index where the key starts!");

    //TODO: ???
    /*
        .rodata:00000000014F8349 ; _BYTE byte_14F8349[128]
        .rodata:00000000014F8349 byte_14F8349    DCB 0x92, 0x88, 0x20, 0x65, 0xA3, 0x11, 0x73, 0xD7, 0xA5
        .rodata:00000000014F8349                                         ; DATA XREF: MetadataLoader__LoadMetadataFile+128↓o
        .rodata:00000000014F8349                                         ; MetadataLoader__LoadMetadataFile+130↓o
        .rodata:00000000014F8352                 DCB 0x82, 0x81, 0x62, 5, 0xD, 0x56, 7, 0xAB, 0xDC, 0x77
        .rodata:00000000014F835C                 DCB 0xCA, 0x40, 0xC9, 0xA, 0xD1, 0x99, 0xF5, 0x63, 0xCE
        .rodata:00000000014F8365                 DCB 0xE4, 0xDC, 0xAD, 0x96, 0x60, 0xD7, 0x7B, 0xD, 0xA2
        .rodata:00000000014F836E                 DCB 0x77, 0x6D, 0xCE, 0x39, 0xA5, 0xF8, 1, 0x27, 0xF1
        .rodata:00000000014F8377                 DCB 0x37, 0xE5, 0x24, 0xF9, 0x2B, 0xB6, 0xA1, 0xE0, 0xA3
        .rodata:00000000014F8380                 DCB 0xC8, 0x7E, 0x4F, 0xCB, 0xAE, 0xAE, 0xA5, 0xF3, 0xC8
        .rodata:00000000014F8389                 DCB 0xD5, 0xEB, 1, 0x2D, 0x92, 0x48, 0x65, 0x33, 0x6F
        .rodata:00000000014F8392                 DCB 0xA9, 0x90, 0x9B, 0xD1, 8, 0xA9, 0xA8, 0xBD, 0x7D
        .rodata:00000000014F839B                 DCB 0xA9, 0xEB, 0xB0, 0xF7, 0xF4, 0x80, 0x33, 0xB2, 0x8F
        .rodata:00000000014F83A4                 DCB 0x52, 0xAB, 0xBE, 0x20, 0x94, 0xB2, 0x30, 0x2C, 0x3C
        .rodata:00000000014F83AD                 DCB 0xEF, 0xA, 0x53, 0xDC, 0x93, 0xF8, 0x46, 0xF8, 0x50
        .rodata:00000000014F83B6                 DCB 7, 0xF7, 0x75, 0xA5, 0x23, 0xF1, 0x30, 0xFB, 7, 0x17
        .rodata:00000000014F83C0                 DCB 0xDD, 0xF7, 0x81, 0xF9, 0xE0, 0xB9, 0x12, 0x88, 0xB1
    */
    key_len = 128;
    decrypt(metadata_buffer, key_start_idx + libil2cpp_buffer, metadata_size, key_len);
    fwrite(metadata_buffer, 1, metadata_size, decrypted_metadata);

    free(metadata_buffer);
    free(libil2cpp_buffer);
    fclose(encrypted_metadata);
    fclose(libil2cpp);
    fclose(decrypted_metadata);

    return EXIT_SUCCESS;
    error_exit:
        if (metadata_buffer) free(metadata_buffer);
        if (libil2cpp_buffer) free(libil2cpp_buffer);
        if (encrypted_metadata) fclose(encrypted_metadata);
        if (libil2cpp) fclose(libil2cpp);
        if (decrypted_metadata) fclose(decrypted_metadata);
        return EXIT_FAILURE;
}
