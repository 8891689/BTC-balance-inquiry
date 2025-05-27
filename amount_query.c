// Amount_Query.c
// gcc amount_query.c sha256.c ripemd160.c secp256k1.c keccak256.c bech32.c base58.c -O3 -o aq
// author：https://github.com/8891689
// Assist in creation ：gemini
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "sha256.h"
#include "ripemd160.h"
#include "secp256k1.h"
#include "keccak256.h"
#include "bech32.h"
#include "base58.h"

#include <strings.h> // For strcasecmp (POSIX)

#define MAX_LINE_LEN 512
#define MAX_ADDR_LEN 128
#define MAX_AMOUNT_STR_LEN 30
#define FORMATTED_BTC_BUF_LEN (MAX_AMOUNT_STR_LEN + 10)

#define MAX_DATA_FILES 50
#define MAX_FILENAME_LEN 256

#define MAX_HEX_INPUT_LEN 260

#define BTC_P2PKH_VERSION_BYTE 0x00
#define BTC_P2SH_VERSION_BYTE  0x05

// --- Utility Functions ---
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_string_to_bytes(const char *hex_str, uint8_t *out_bytes, size_t out_len_max) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) return -1;
    if ((hex_len / 2) > out_len_max) return -2;

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_char_to_int(hex_str[2 * i]);
        int lo = hex_char_to_int(hex_str[2 * i + 1]);
        if (hi == -1 || lo == -1) return -3;
        out_bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex_len / 2;
}

void bytes_to_hex_string(const uint8_t *bytes, size_t len, char *hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

// --- Address Amount Lookup Functions ---
void format_btc_amount(const char *raw_amount_str, char *formatted_btc_str, size_t formatted_buf_size) {
    int len = strlen(raw_amount_str);
    char temp_satoshi_part[9];

    if (formatted_buf_size > 0) formatted_btc_str[0] = '\0';
    else return;

    if (len == 0) {
        snprintf(formatted_btc_str, formatted_buf_size, "0.00000000 BTC");
        return;
    }
    for(int i = 0; i < len; ++i) {
        if (!isdigit(raw_amount_str[i])) {
            snprintf(formatted_btc_str, formatted_buf_size, "[Invalid amount format] BTC"); // English
            return;
        }
    }

    if (len <= 8) {
        int num_leading_zeros = 8 - len;
        for (int i = 0; i < num_leading_zeros; i++) temp_satoshi_part[i] = '0';
        strcpy(temp_satoshi_part + num_leading_zeros, raw_amount_str);
        temp_satoshi_part[8] = '\0';
        snprintf(formatted_btc_str, formatted_buf_size, "0.%s BTC", temp_satoshi_part);
    } else {
        int int_part_len = len - 8;
        char int_part_temp[MAX_AMOUNT_STR_LEN];
        char frac_part_temp[9];

        strncpy(int_part_temp, raw_amount_str, int_part_len);
        int_part_temp[int_part_len] = '\0';
        strncpy(frac_part_temp, raw_amount_str + int_part_len, 8);
        frac_part_temp[8] = '\0';
        snprintf(formatted_btc_str, formatted_buf_size, "%s.%s BTC", int_part_temp, frac_part_temp);
    }
}

int search_address_in_datafile(const char *address_to_find, FILE *data_fp,
                               char *found_address_buf, size_t found_address_buf_size,
                               char *raw_amount_buf, size_t raw_amount_buf_size) {
    char line[MAX_LINE_LEN];
    char current_file_addr[MAX_ADDR_LEN];

    if (fseek(data_fp, 0, SEEK_SET) != 0) {
        // perror("search_address_in_datafile: fseek error"); // Keep for debugging if needed
        return 0;
    }

    while (fgets(line, sizeof(line), data_fp)) {
        line[strcspn(line, "\n\r")] = 0;

        char *tab_ptr = strchr(line, '\t');
        if (tab_ptr == NULL) continue;

        size_t addr_len = tab_ptr - line;
        if (addr_len >= MAX_ADDR_LEN || addr_len >= found_address_buf_size) continue;

        strncpy(current_file_addr, line, addr_len);
        current_file_addr[addr_len] = '\0';

        if (strcasecmp(address_to_find, current_file_addr) == 0) {
            const char *amount_start_ptr = tab_ptr + 1;
            size_t actual_amount_len = strlen(amount_start_ptr);
            size_t copy_len = (actual_amount_len < MAX_AMOUNT_STR_LEN -1 && actual_amount_len < raw_amount_buf_size -1)
                              ? actual_amount_len
                              : ((MAX_AMOUNT_STR_LEN -1 < raw_amount_buf_size -1) ? MAX_AMOUNT_STR_LEN -1 : raw_amount_buf_size -1);

            strncpy(raw_amount_buf, amount_start_ptr, copy_len);
            raw_amount_buf[copy_len] = '\0';

            strncpy(found_address_buf, current_file_addr, found_address_buf_size -1);
            found_address_buf[found_address_buf_size-1] = '\0';

            return 1;
        }
    }
    return 0;
}

void process_lookup_for_one_address(const char *address_to_find, const char* derivation_info_unused,
                                    char **data_filenames, int num_data_files) {
    char found_addr_str[MAX_ADDR_LEN];
    char raw_amount_str[MAX_AMOUNT_STR_LEN];
    char formatted_btc_output[FORMATTED_BTC_BUF_LEN];
    bool found = false;

    (void)derivation_info_unused; // Mark as unused

    if (num_data_files == 0) {
        // fprintf(stderr, "Warning: No data files available for query.\n");
        return;
    }

    for (int i = 0; i < num_data_files; ++i) {
        FILE *data_fp = fopen(data_filenames[i], "r");
        if (!data_fp) {
            // fprintf(stderr, "Warning: Cannot open data file '%s'\n", data_filenames[i]);
            continue;
        }

        if (search_address_in_datafile(address_to_find, data_fp,
                                       found_addr_str, sizeof(found_addr_str),
                                       raw_amount_str, sizeof(raw_amount_str))) {
            format_btc_amount(raw_amount_str, formatted_btc_output, sizeof(formatted_btc_output));
            printf("Address: %s\n", found_addr_str);
            printf("Amount: %s\n", formatted_btc_output);
            found = true;
            fclose(data_fp);
            break;
        }
        fclose(data_fp);
    }

    if (!found) {
        // No output if not found, as per "simple output"
    }
}


// --- BTC Address Generation ---
void pubkey_to_hash160(const uint8_t *pubkey_bytes, size_t pubkey_len, uint8_t hash160_out[RIPEMD160_DIGEST_LENGTH]) {
    uint8_t sha256_hash[SHA256_BLOCK_SIZE];
    sha256(pubkey_bytes, pubkey_len, sha256_hash);
    ripemd160(sha256_hash, SHA256_BLOCK_SIZE, hash160_out);
}

int hash160_to_p2pkh_address(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], char *address_out, size_t address_out_len) {
    uint8_t payload[1 + RIPEMD160_DIGEST_LENGTH];
    payload[0] = BTC_P2PKH_VERSION_BYTE;
    memcpy(payload + 1, hash160, RIPEMD160_DIGEST_LENGTH);

    char* encoded = base58_encode_check(payload, sizeof(payload));
    if (!encoded) return 0;

    strncpy(address_out, encoded, address_out_len -1);
    address_out[address_out_len-1] = '\0';
    free(encoded);
    return 1;
}

int hash160_to_p2wpkh_address(const uint8_t hash160[RIPEMD160_DIGEST_LENGTH], char *address_out, size_t address_out_len) {
    if (address_out_len < 91) return 0;
    return segwit_addr_encode(address_out, "bc", 0, hash160, RIPEMD160_DIGEST_LENGTH);
}

int hash160_to_p2sh_p2wpkh_address(const uint8_t hash160_compressed_pubkey[RIPEMD160_DIGEST_LENGTH], char *address_out, size_t address_out_len) {
    uint8_t redeem_script[2 + RIPEMD160_DIGEST_LENGTH];
    redeem_script[0] = 0x00;
    redeem_script[1] = 0x14;
    memcpy(redeem_script + 2, hash160_compressed_pubkey, RIPEMD160_DIGEST_LENGTH);

    uint8_t script_hash160[RIPEMD160_DIGEST_LENGTH];
    pubkey_to_hash160(redeem_script, sizeof(redeem_script), script_hash160);

    uint8_t p2sh_payload[1 + RIPEMD160_DIGEST_LENGTH];
    p2sh_payload[0] = BTC_P2SH_VERSION_BYTE;
    memcpy(p2sh_payload + 1, script_hash160, RIPEMD160_DIGEST_LENGTH);

    char* encoded = base58_encode_check(p2sh_payload, sizeof(p2sh_payload));
    if (!encoded) return 0;

    strncpy(address_out, encoded, address_out_len -1);
    address_out[address_out_len-1] = '\0';
    free(encoded);
    return 1;
}

// --- ETH Address Generation ---
int uncompressed_pubkey_xy_to_eth_address(const uint8_t pubkey_xy_bytes[64], char *address_out, size_t address_out_len) {
    if (address_out_len < 43) return 0;

    uint8_t keccak_hash[32];
    keccak_256(pubkey_xy_bytes, 64, keccak_hash);

    strcpy(address_out, "0x");
    bytes_to_hex_string(keccak_hash + 12, 20, address_out + 2);
    return 1;
}

// --- Input Handling Functions ---
void handle_private_key_input(const char *privkey_str, char **data_filenames, int num_data_files) {
    uint8_t priv_key_bytes[32];
    int key_len = -1;
    ECPoint pub_ecpoint;
    BigInt priv_bigint;

    size_t decoded_len = 0;
    uint8_t *decoded_wif = base58_decode_check(privkey_str, &decoded_len);
    if (decoded_wif != NULL) {
        if (decoded_wif[0] == 0x80 && (decoded_len == 33 || decoded_len == 34)) {
             memcpy(priv_key_bytes, decoded_wif + 1, 32);
             key_len = 32;
             // printf("  WIF private key detected.\n"); // Removed
        }
        free(decoded_wif);
    }

    if (key_len == -1) {
        if (strlen(privkey_str) == 64) {
            int bytes_written = hex_string_to_bytes(privkey_str, priv_key_bytes, sizeof(priv_key_bytes));
            if (bytes_written == 32) {
                 key_len = 32;
                 // printf("  Hex private key detected.\n"); // Removed
            }
        }
    }

    if (key_len != 32) {
        fprintf(stderr, "Error: Invalid private key format or length (key_len: %d).\n", key_len); // English
        // printf("  Private key processing finished.\n\n"); // Removed
        return;
    }

    bytes_be_to_bigint(priv_key_bytes, &priv_bigint);
    private_to_public_key(&pub_ecpoint, &priv_bigint);
    if (pub_ecpoint.infinity) {
        fprintf(stderr, "Error: Public key derived from private key is point at infinity.\n"); // English
        // printf("  Private key processing finished.\n\n"); // Removed
        return;
    }

    char derived_addr[MAX_ADDR_LEN];
    uint8_t hash160_val[RIPEMD160_DIGEST_LENGTH];
    uint8_t x_coord_bytes[32];
    uint8_t y_coord_bytes[32];
    uint8_t comp_pubkey_bytes[33];
    uint8_t uncomp_pubkey_bytes[65];

    bigint_to_bytes_be(&pub_ecpoint.x, x_coord_bytes);
    bigint_to_bytes_be(&pub_ecpoint.y, y_coord_bytes);

    comp_pubkey_bytes[0] = is_odd(&pub_ecpoint.y) ? 0x03 : 0x02;
    memcpy(comp_pubkey_bytes + 1, x_coord_bytes, 32);

    uncomp_pubkey_bytes[0] = 0x04;
    memcpy(uncomp_pubkey_bytes + 1, x_coord_bytes, 32);
    memcpy(uncomp_pubkey_bytes + 33, y_coord_bytes, 32);

    // Deriving from compressed public key
    pubkey_to_hash160(comp_pubkey_bytes, sizeof(comp_pubkey_bytes), hash160_val);
    if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
        process_lookup_for_one_address(derived_addr, "P2PKH (Priv->Comp)", data_filenames, num_data_files);
    }
    if (hash160_to_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
        process_lookup_for_one_address(derived_addr, "P2WPKH (Priv->Comp)", data_filenames, num_data_files);
    }
    if (hash160_to_p2sh_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
        process_lookup_for_one_address(derived_addr, "P2SH-P2WPKH (Priv->Comp)", data_filenames, num_data_files);
    }

    // Deriving from uncompressed public key
    pubkey_to_hash160(uncomp_pubkey_bytes, sizeof(uncomp_pubkey_bytes), hash160_val);
    if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
        process_lookup_for_one_address(derived_addr, "P2PKH (Priv->Uncomp)", data_filenames, num_data_files);
    }
    if (uncompressed_pubkey_xy_to_eth_address(uncomp_pubkey_bytes + 1, derived_addr, sizeof(derived_addr))) {
        process_lookup_for_one_address(derived_addr, "ETH (Priv->Pub)", data_filenames, num_data_files);
    }
    // printf("  Private key processing finished.\n\n"); // Removed
}

void handle_public_key_input(const char *pubkey_hex_str, char **data_filenames, int num_data_files) {
    uint8_t input_pubkey_bytes[65];
    int key_len = hex_string_to_bytes(pubkey_hex_str, input_pubkey_bytes, sizeof(input_pubkey_bytes));

    ECPoint ec_point_from_input;
    bool point_successfully_obtained = false;

    if (key_len == 33 && (input_pubkey_bytes[0] == 0x02 || input_pubkey_bytes[0] == 0x03)) {
        // printf("  Compressed public key detected.\n"); // Removed
        if (decompress_pubkey_bytes(input_pubkey_bytes, &ec_point_from_input)) {
            point_successfully_obtained = true;
        } else {
            fprintf(stderr, "Error: Failed to decompress input compressed public key.\n"); // English
        }
    } else if (key_len == 65 && input_pubkey_bytes[0] == 0x04) {
        // printf("  Uncompressed public key detected.\n"); // Removed
        bytes_be_to_bigint(input_pubkey_bytes + 1, &ec_point_from_input.x);
        bytes_be_to_bigint(input_pubkey_bytes + 33, &ec_point_from_input.y);
        ec_point_from_input.infinity = false;
        point_successfully_obtained = true;
    } else {
        fprintf(stderr, "Error: Invalid public key format or length.\n"); // English
        // printf("  Public key processing finished.\n\n"); // Removed
        return;
    }

    char derived_addr[MAX_ADDR_LEN];
    uint8_t hash160_val[RIPEMD160_DIGEST_LENGTH];

    // Deriving BTC addresses from original input public key form
    if (key_len == 33) {
        pubkey_to_hash160(input_pubkey_bytes, key_len, hash160_val);
        if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
            process_lookup_for_one_address(derived_addr, "P2PKH (Input Comp)", data_filenames, num_data_files);
        }
        if (hash160_to_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
            process_lookup_for_one_address(derived_addr, "P2WPKH (Input Comp)", data_filenames, num_data_files);
        }
        if (hash160_to_p2sh_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
           process_lookup_for_one_address(derived_addr, "P2SH-P2WPKH (Input Comp)", data_filenames, num_data_files);
        }
    } else if (key_len == 65) {
         pubkey_to_hash160(input_pubkey_bytes, key_len, hash160_val);
        if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
           process_lookup_for_one_address(derived_addr, "P2PKH (Input Uncomp)", data_filenames, num_data_files);
        }
    }

    if (point_successfully_obtained) {
        uint8_t x_coord_bytes[32];
        uint8_t y_coord_bytes[32];
        uint8_t unified_comp_pubkey_bytes[33];
        uint8_t unified_uncomp_pubkey_bytes[65];

        bigint_to_bytes_be(&ec_point_from_input.x, x_coord_bytes);
        bigint_to_bytes_be(&ec_point_from_input.y, y_coord_bytes);

        unified_comp_pubkey_bytes[0] = is_odd(&ec_point_from_input.y) ? 0x03 : 0x02;
        memcpy(unified_comp_pubkey_bytes + 1, x_coord_bytes, 32);

        unified_uncomp_pubkey_bytes[0] = 0x04;
        memcpy(unified_uncomp_pubkey_bytes + 1, x_coord_bytes, 32);
        memcpy(unified_uncomp_pubkey_bytes + 33, y_coord_bytes, 32);

        if (key_len == 65) { // If original was uncompressed, derive from compressed form
            pubkey_to_hash160(unified_comp_pubkey_bytes, sizeof(unified_comp_pubkey_bytes), hash160_val);
            if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
                process_lookup_for_one_address(derived_addr, "P2PKH (ECPoint->Comp)", data_filenames, num_data_files);
            }
            if (hash160_to_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
                process_lookup_for_one_address(derived_addr, "P2WPKH (ECPoint->Comp)", data_filenames, num_data_files);
            }
            if (hash160_to_p2sh_p2wpkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
               process_lookup_for_one_address(derived_addr, "P2SH-P2WPKH (ECPoint->Comp)", data_filenames, num_data_files);
            }
        }

        if (key_len == 33) { // If original was compressed, derive P2PKH from uncompressed form
            pubkey_to_hash160(unified_uncomp_pubkey_bytes, sizeof(unified_uncomp_pubkey_bytes), hash160_val);
            if (hash160_to_p2pkh_address(hash160_val, derived_addr, sizeof(derived_addr))) {
               process_lookup_for_one_address(derived_addr, "P2PKH (ECPoint->Uncomp)", data_filenames, num_data_files);
            }
        }
        // Derive ETH address from uncompressed form (always, if point was obtained)
        if (uncompressed_pubkey_xy_to_eth_address(unified_uncomp_pubkey_bytes + 1, derived_addr, sizeof(derived_addr))) {
           process_lookup_for_one_address(derived_addr, "ETH (ECPoint)", data_filenames, num_data_files);
        }

    } else if (key_len == 33 && !point_successfully_obtained) {
        // fprintf(stderr, "Warning: Cannot perform further derivations due to failed decompression of compressed public key.\n"); // Removed
    }
    // printf("  Public key processing finished.\n\n"); // Removed
}

void handle_hash160_input(const char *hash160_hex_str, char **data_filenames, int num_data_files) {
    uint8_t hash160_bytes[RIPEMD160_DIGEST_LENGTH];
    char derived_addr[MAX_ADDR_LEN];

    if (strlen(hash160_hex_str) != 40) {
        fprintf(stderr, "Error: Hash160 hex string must be 40 characters long.\n"); // English
        return;
    }
    int len = hex_string_to_bytes(hash160_hex_str, hash160_bytes, sizeof(hash160_bytes));

    if (len != RIPEMD160_DIGEST_LENGTH) {
        fprintf(stderr, "Error: Failed to convert Hash160 or incorrect length.\n"); // English
        return;
    }
    // printf("  Hash160 detected.\n"); // Removed

    if (hash160_to_p2pkh_address(hash160_bytes, derived_addr, sizeof(derived_addr))) {
       process_lookup_for_one_address(derived_addr, "P2PKH (from Hash160)", data_filenames, num_data_files);
    }
    if (hash160_to_p2wpkh_address(hash160_bytes, derived_addr, sizeof(derived_addr))) {
       process_lookup_for_one_address(derived_addr, "P2WPKH (from Hash160)", data_filenames, num_data_files);
    }
    if (hash160_to_p2sh_p2wpkh_address(hash160_bytes, derived_addr, sizeof(derived_addr))) {
       process_lookup_for_one_address(derived_addr, "P2SH-P2WPKH (from Hash160)", data_filenames, num_data_files);
    }
    // printf("  Hash160 processing finished.\n\n"); // Removed
}


void print_usage(const char *prog_name) {
    fprintf(stderr, "Program will automatically scan for .txt files in the current directory as databases (unless -f is specified).\n"); // English
    fprintf(stderr, "Usage:\n"); // English
    fprintf(stderr, "  %s [-f <datafile1> [<datafile2> ...]] (Interactive mode)\n", prog_name); // English
    fprintf(stderr, "  %s [-f <datafile1> ...] <address>\n", prog_name);
    fprintf(stderr, "  %s [-f <datafile1> ...] -k <private_key_WIF_or_HEX>\n", prog_name);
    fprintf(stderr, "  %s [-f <datafile1> ...] -p <public_key_HEX>\n", prog_name);
    fprintf(stderr, "  %s [-f <datafile1> ...] -h <Hash160_HEX>\n", prog_name);
    fprintf(stderr, "  %s [-f <datafile1> ...] <input_file> <output_file> [-x]\n", prog_name);
    fprintf(stderr, "Options:\n"); // English
    fprintf(stderr, "  -f <file_list> : Specify one or more database files for query (overrides auto-scan).\n"); // English
    fprintf(stderr, "  -x             : (Batch mode) Output only found addresses, without amount.\n"); // English
}

void process_batch_lookup(const char *input_filename, const char *output_filename,
                          char **data_filenames, int num_data_files, int include_amount) {
    FILE *input_fp = fopen(input_filename, "r");
    if (!input_fp) {
        perror("Error opening input address file"); // perror is usually English
        fprintf(stderr, "Filename: %s\n", input_filename);
        return;
    }

    FILE *output_fp = fopen(output_filename, "w");
    if (!output_fp) {
        perror("Error creating/opening output results file"); // perror is usually English
        fprintf(stderr, "Filename: %s\n", output_filename);
        fclose(input_fp);
        return;
    }

    char search_addr_line[MAX_ADDR_LEN + 2];
    char found_addr_str[MAX_ADDR_LEN];
    char raw_amount_str[MAX_AMOUNT_STR_LEN];
    char formatted_btc_output[FORMATTED_BTC_BUF_LEN];
    int count_found = 0;
    int count_processed = 0;

    // Minimal console output for batch mode start
    // printf("Processing batch: input '%s', output '%s'\n", input_filename, output_filename);

    while (fgets(search_addr_line, sizeof(search_addr_line), input_fp)) {
        search_addr_line[strcspn(search_addr_line, "\n\r")] = 0;
        count_processed++;
        if (strlen(search_addr_line) == 0) continue;

        // bool found_this_addr = false; // Not strictly needed if we break on first find
        for (int i = 0; i < num_data_files; ++i) {
            FILE *data_fp = fopen(data_filenames[i], "r");
            if (!data_fp) {
                // fprintf(stderr, "Warning: Cannot open data file '%s' for address '%s' in batch mode. Skipping.\n", data_filenames[i], search_addr_line); // Removed
                continue;
            }

            if (search_address_in_datafile(search_addr_line, data_fp,
                                           found_addr_str, sizeof(found_addr_str),
                                           raw_amount_str, sizeof(raw_amount_str))) {
                count_found++;
                // found_this_addr = true;
                if (include_amount) {
                    format_btc_amount(raw_amount_str, formatted_btc_output, sizeof(formatted_btc_output));
                    fprintf(output_fp, "%s\t%s\n", found_addr_str, formatted_btc_output);
                } else {
                    fprintf(output_fp, "%s\n", found_addr_str);
                }
                fclose(data_fp);
                break;
            }
            fclose(data_fp);
        }
    }

    fclose(input_fp);
    fclose(output_fp);
    printf("Batch processing complete. Processed: %d, Found: %d. Results saved to: %s\n", count_processed, count_found, output_filename); // English
}

#ifdef _WIN32
int scan_directory_for_data_files(char **file_list, int max_files) {
    int count = 0;
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(".\\*.txt", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (count < max_files) {
                file_list[count] = _strdup(findFileData.cFileName);
                if (file_list[count] == NULL) {
                    perror("scan_directory_for_data_files: _strdup failed");
                } else {
                    count++;
                }
            } else {
                // fprintf(stderr, "Warning: Found more data files than limit (%d). Using first %d.\n", max_files, max_files); // Removed
                break;
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);
    FindClose(hFind);
    return count;
}
#else // POSIX
int scan_directory_for_data_files(char **file_list, int max_files) {
    int count = 0;
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    dir = opendir(".");
    if (dir == NULL) {
        perror("Cannot open current directory"); // English
        return 0;
    }
    while ((entry = readdir(dir)) != NULL && count < max_files) {
        char full_path[MAX_FILENAME_LEN];
        snprintf(full_path, sizeof(full_path), "./%s", entry->d_name);
        if (stat(full_path, &file_stat) == -1) {
            continue;
        }
        if (S_ISREG(file_stat.st_mode)) {
            const char *dot = strrchr(entry->d_name, '.');
            if (dot && strcmp(dot, ".txt") == 0) {
                file_list[count] = strdup(entry->d_name);
                if (file_list[count] == NULL) {
                    perror("scan_directory_for_data_files: strdup failed");
                } else {
                    count++;
                }
            }
        }
    }
    closedir(dir);
    return count;
}
#endif

int main(int argc, char *argv[]) {
    char *data_files_storage[MAX_DATA_FILES];
    char **data_files_to_use = data_files_storage;
    int num_data_files_to_use = 0;
    int arg_offset = 1;
    bool use_cmd_line_df = false; // Renamed from use_cmd_line_df to use_cmd_line_f

    if (argc > 1 && strcmp(argv[1], "-f") == 0) { // Changed -df to -f
        use_cmd_line_df = true;
        arg_offset = 2;
        while (arg_offset < argc && num_data_files_to_use < MAX_DATA_FILES) {
            if (argv[arg_offset][0] == '-') break;
            data_files_to_use[num_data_files_to_use++] = argv[arg_offset++];
        }
        if (num_data_files_to_use == 0 && arg_offset -1 == 1){
             fprintf(stderr, "Error: -f option requires at least one database filename.\n"); // English
             print_usage(argv[0]);
             return 1;
        }
    }

    if (!use_cmd_line_df) {
        num_data_files_to_use = scan_directory_for_data_files(data_files_to_use, MAX_DATA_FILES);
    }

    if (num_data_files_to_use == 0) {
        fprintf(stderr, "Fatal Error: No database files available for query.\n"); // English
        if (!use_cmd_line_df) fprintf(stderr, "  (Ensure .txt data files are in the current directory, or use -f to specify files)\n"); // English
        print_usage(argv[0]);
        return 1;
    }

    bool can_read_any_db = false;
    for (int i = 0; i < num_data_files_to_use; ++i) {
        FILE *test_fp = fopen(data_files_to_use[i], "r");
        if (test_fp) {
            can_read_any_db = true;
            fclose(test_fp);
            break;
        }
    }
    if (!can_read_any_db) {
        fprintf(stderr, "Fatal Error: None of the selected database files could be opened/read.\n"); // English
        for (int i=0; i < num_data_files_to_use; ++i) fprintf(stderr, " - %s\n", data_files_to_use[i]);
        return 1;
    }

    int effective_argc = argc - (arg_offset - 1);
    char **effective_argv = argv + (arg_offset - 1);

    if (effective_argc == 1) {
        char search_input[MAX_HEX_INPUT_LEN + 2];
        // Minimal interactive mode start
        printf("Interactive mode. Using %d data file(s).\nEnter address to query (or 'exit' to quit):\n", num_data_files_to_use); // English
        while (1) {
            printf("> "); // Prompt for interactive mode
            if (fgets(search_input, sizeof(search_input), stdin) == NULL) break;
            search_input[strcspn(search_input, "\n\r")] = 0;
            if (strcasecmp(search_input, "exit") == 0) break; // Case-insensitive exit
            if (strlen(search_input) == 0) continue;
            process_lookup_for_one_address(search_input, "Interactive", data_files_to_use, num_data_files_to_use);
            // printf("\n"); // Removed extra newline
        }
    } else if (effective_argc == 2) {
        process_lookup_for_one_address(effective_argv[1], "CLI Direct", data_files_to_use, num_data_files_to_use);
    } else if (effective_argc == 3) {
        if (strcmp(effective_argv[1], "-k") == 0) {
            handle_private_key_input(effective_argv[2], data_files_to_use, num_data_files_to_use);
        } else if (strcmp(effective_argv[1], "-p") == 0) {
            handle_public_key_input(effective_argv[2], data_files_to_use, num_data_files_to_use);
        } else if (strcmp(effective_argv[1], "-h") == 0) {
            handle_hash160_input(effective_argv[2], data_files_to_use, num_data_files_to_use);
        } else {
            process_batch_lookup(effective_argv[1], effective_argv[2], data_files_to_use, num_data_files_to_use, 1);
        }
    } else if (effective_argc == 4) {
        if (strcmp(effective_argv[3], "-x") == 0) {
            process_batch_lookup(effective_argv[1], effective_argv[2], data_files_to_use, num_data_files_to_use, 0);
        } else {
            print_usage(argv[0]);
        }
    } else {
        print_usage(argv[0]);
    }

    if (!use_cmd_line_df) {
        for (int i = 0; i < num_data_files_to_use; ++i) {
            free(data_files_to_use[i]);
        }
    }
    return 0;
}
