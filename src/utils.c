/*
 * This file is part of the snmpfs project (http://snmpfs.x25.pm).
 * snmpfs is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the license, or any later
 * version.  See LICENSE file for further copyright and license details.
 */

#include "common.h"

#include <iconv.h>
#include <time.h>
#include "utils.h"

ssize_t to_hex(const uint8_t *byte_array, const size_t byte_array_size,
        char *destination, const size_t destination_max)
{
    if (destination_max < 3 + (byte_array_size << 1))
        return -1;

    sprintf(destination, "0x");
    for (int i = 0; i < byte_array_size; i++) {
        sprintf(&destination[(i + 1) << 1], "%02x", byte_array[i]);
    }
    destination[2 + (byte_array_size << 1)] = '\0';

    return 3 + (byte_array_size << 1);
}

ssize_t from_hex(const char *hex_str, uint8_t *byte_array,
        const size_t byte_array_max)
{
    if (hex_str == NULL)
        return 0;

    int offset = 0;
    if (hex_str[0] == '0' && hex_str[1] == 'x')
        offset += 2;

    int i = 0;
    while (hex_str[offset] != '\0') {
        if (i > byte_array_max) {
            return -1;
        } else if (sscanf((char *) &hex_str[offset], "%2hhx", &byte_array[i]) != 1) {
            return -1;
        } else {
            i++;
            offset += 2;
        }
    }

    return i;
}

char *strconcat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1) + strlen(s2) + 1);
    if (result == NULL)
        return NULL;
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void *memdup(const void *src, size_t src_len)
{
    void *dup = malloc(src_len);

    if (dup == NULL)
        return NULL;

    memcpy(dup, src, src_len);
    return dup;
}

int is_utf8(const uint8_t *src, const size_t len)
{
    uint8_t dst[len];
    char *inbuf = (char *) src;
    size_t inbytesleft = len;
    char *outbuf = (char *) &dst;
    size_t outbytesleft = len;

    iconv_t conv = iconv_open("UTF-8", "UTF-8");
    if (conv == (iconv_t) -1)
        return -1;

    iconv(conv, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    iconv_close(conv);
    return inbytesleft != 0 ? -1 : 0;
}

int lenient_strcmp(const char *s1, const char *s2)
{
    const char *p1 = s1;
    const char *p2 = s2;

    while (*p1) {
        while (*p1 && !isalnum(*p1))
            p1++;
        if (!*p1)
            break;
        while (*p2 && !isalnum(*p2))
            p2++;
        if (!*p2)
            return 1;
        if (tolower(*p1) < tolower(*p2))
            return -1;
        if (tolower(*p1) > tolower(*p2))
            return  1;
        p1++;
        p2++;
    }

    if (*p2)
        return -1;

    return 0;
}

uint32_t get_uptime(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        syslog(LOG_ERR, "failed to determine system uptime");
        return -1;
    } else {
        return (uint32_t) ts.tv_sec;
    }
}

int mkpath(const char *path, const mode_t mode) {
    if (strlen(path) < 1)
        return -1;

    char *dup = strdup(path);
    if (dup == NULL)
        return -1;

    for (char *p = strchr(dup + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(dup, mode) && errno != EEXIST) {
            free(dup);
            return -1;
        }
        *p = '/';
    }

    free(dup);
    return 0;
}

//int read_from_file(const char *path, uint8_t **dst, size_t *dst_len)
//{
//    int ret = 0;
//    FILE *f = fopen(path, "rb");
//    if (f == NULL)
//        return -1;
//
//    if (*dst == NULL) {
//        if (fseek(f, 0, SEEK_END)) {
//            ret = -1;
//            goto end;
//        } else if ((*dst_len = ftell(f)) == -1) {
//            ret = -1;
//            goto end;
//        } else if ((*dst = malloc(*dst_len)) == NULL) {
//            ret = -1;
//            goto end;
//        }
//
//        rewind(f);
//
//        int val = fread(*dst, *dst_len, 1, f);
//        if (val != 1) {
//            ret = -1;
//            free(*dst);
//            *dst = NULL;
//        }
//    } else {
//        size_t read_len = fread(*dst, 1, *dst_len, f);
//        *dst_len = read_len;
//    }
//
//end:
//    fclose(f);
//    return ret;
//}
//
//int read_unsigned_from_file(const char *file, uint32_t *dst)
//{
//    FILE *f = NULL;
//    char line[16];
//
//    if ((f = fopen(file, "r")) == NULL) {
//        return -1;
//    } else if (line != fgets(line, sizeof(line), f) ||
//        sscanf(line, "%"PRIu32, dst) != 1) {
//        fclose(f);
//        return -1;
//    }
//
//    fclose(f);
//    return 0;
//}
//
//int read_unsigned64_from_file(const char *file, uint64_t *dst)
//{
//    FILE *f = NULL;
//    char line[16];
//
//    if ((f = fopen(file, "r")) == NULL) {
//        return -1;
//    } else if (line != fgets(line, sizeof(line), f) ||
//        sscanf(line, "%"PRIu64, dst) != 1) {
//        fclose(f);
//        return -1;
//    }
//
//    fclose(f);
//    return 0;
//}
//
//int write_to_file(const char *path, const uint8_t *val, const size_t val_len)
//{
//    FILE* f = fopen(path, "wb");
//    int ret = 0;
//
//    if (f == NULL) {
//        return -1;
//    } else if (fwrite(val, 1, val_len, f) != val_len) {
//        ret = -1;
//    }
//
//    fclose(f);
//    return ret;
//}
//
//void set_netmask(const int prefix_len, uint8_t *buf, const size_t buf_len)
//{
//    memset(buf, 0, buf_len);
//    int rem = prefix_len;
//    int i = 0;
//    while (rem > 8 && i < buf_len) {
//        buf[i++] = 0xff;
//        rem -= 8;
//    }
//    if (rem > 0 && i < buf_len)
//        buf[i] = 0xff << (8 - rem);
//}
//
//char *trim_string(char *str)
//{
//    if (str == NULL || str[0] == '\0')
//        return str;
//
//    size_t len = strlen(str);
//    char *start = str;
//    char *end = str + len;
//
//    while (isspace((unsigned char) *start))
//        start++;
//    if(end != start)
//        while ((isspace((unsigned char) *(--end)) || *end == '\n') && end != start);
//
//    if(str + len - 1 != end)
//        *(end + 1) = '\0';
//    else if(start != str && end == start)
//        *str = '\0';
//
//    end = str;
//    if(start != str) {
//        while(*start)
//            *end++ = *start++;
//        *end = '\0';
//    }
//
//    return str;
//}
