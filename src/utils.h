/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include "common.h"

#define XSTRING(s)  STRING(s)
#define STRING(x)   #x
#define HEX_LEN(x)  (3 + (x << 1))

#define SINGLE_PARAM(...) __VA_ARGS__

#ifndef min
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

/**
 * to_hex - Converts byte array to null-terminated string of hex characters.
 *
 * @param byte_array      IN - pointer to start of byte array
 * @param byte_array_size IN - number of valid bytes left in buffer
 * @param destination     OUT - pointer to start of output buffer
 * @param destination_max IN - maximum size of output buffer
 *
 * @return size of resulting string (including null terminator),
 * or -1 on any error
 */
ssize_t to_hex(const uint8_t *byte_array, const size_t byte_array_size,
        char *destination, const size_t destination_max);

/**
 * from_hex - Converts hex string to sequence of bytes.
 *
 * @param hex_str         IN - pointer to start of hex string
 * @param byte_array      OUT - pointer to start of output buffer
 * @param byte_array_max  IN - maximum size of output buffer
 *
 * @return size of resulting byte array, or -1 on any error
 */
ssize_t from_hex(const char *hex_str, uint8_t *byte_array,
        const size_t byte_array_max);

/**
 * strconcat - Concatenate the given strings.
 *
 * @param s1 IN - pointer to start of first string
 * @param s2 IN - pointer to start of second string
 *
 * @return pointer to newly allocated string, or NULL if failed
 */
char* strconcat(const char *s1, const char *s2);

/**
 * memdup - Duplicate a chunk of memory
 *
 * @param src IN - pointer to start of memory range
 * @param src_len IN - length of memory range
 *
 * @return pointer to newly allocated copy, or NULL if failed
 */
void *memdup(const void *src, size_t src_len);

/**
 * is_utf8 - Checks if given byte array contains only UTF-8 encoded characters.
 *
 * @param src IN - pointer to start of byte array
 * @param len IN - length of byte array
 *
 * @return 0 if only UTF-8 characters were found, -1 otherwise.
 */
int is_utf8(const uint8_t *src, const size_t len);

/**
 * lenient_strcmp - Performs a case-insensitive string comparison
 * while skipping non-alphanumeric characters on the first string.
 *
 * @param s1 IN - first string (user-provided)
 * @param s2 IN - second string (usually hard-coded)
 *
 * @return 0 if equal, -1 if s1 is smaller than s2, 1 otherwise.
 */
int lenient_strcmp(const char *s1, const char *s2);

/**
 * get_uptime - Returns the system uptime in seconds.
 *
 * @return system uptime (-1 on failure).
 */
uint32_t get_uptime(void);

/**
 * mkpath - Create path including leading components.
 * The newly created directory shall be an empty directory.
 *
 * @param path IN - absolute directory path
 * @param mode IN - file permission bits
 *
 * @return 0 on success, -1 on failure.
 */
int mkpath(const char *path, const mode_t mode);

///**
// * read_from_file - Reads the content of given file into memory.
// *
// * @param path IN - pathname of file to be read
// * @param dst OUT - destination buffer;  if pointer to NULL, a new buffer is allocated.
// * @param dst_len IN/OUT - destination buffer length
// *
// * @return 0 on success, -1 on error.
// */
//int read_from_file(const char *path, uint8_t **dst, size_t *dst_len);
//
///**
// * read_unsigned_from_file - reads unsigned int from file
// *
// * @param file   IN - file name
// * @param dst    OUT - destination
// *
// * @return 0 on success, -1 on failure.
// */
//int read_unsigned_from_file(const char *file, uint32_t *dst);
//
///**
// * read_unsigned64_from_file - reads unsigned 64-bit int from file
// *
// * @param file   IN - file name
// * @param dst    OUT - destination
// *
// * @return 0 on success, -1 on failure.
// */
//int read_unsigned64_from_file(const char *file, uint64_t *dst);
//
///**
// * write_to_file - Write buffer to file.
// *
// * @param path IN - pathname of file to be (over)written
// * @param val IN - source buffer
// * @param val_len IN - source buffer length
// *
// * @return 0 on success, -1 on error.
// */
//int write_to_file(const char *path, const uint8_t *val, const size_t val_len);
//
///**
// * set_netmask - Sets the netmask for given prefix length.
// *
// * @param prefix_len IN - address prefix length
// * @param buf OUT - output buffer
// * @param buf_len IN - buffer length
// */
//void set_netmask(const int prefix_len, uint8_t *buf, const size_t buf_len);
//
///**
// * trim_string - trims the leading and trailing whitespace from the given string.
// *
// * @param str IN/OUT - string to be trimmed
// * @return  offset to new string
// */
//char *trim_string(char *str);

#endif /* SRC_UTILS_H_ */
