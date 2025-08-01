/**
 * Copyright (C) 2025  Lennart Rosam
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "sms_pdu.h"

#define MAX_PDU_LEN 512

// Convert hex string to byte array
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t maxlen) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0 || len / 2 > maxlen) return -1;
    for (size_t i = 0; i < len / 2; ++i) {
        if (!isxdigit(hexstr[2*i]) || !isxdigit(hexstr[2*i+1])) return -1;
        sscanf(hexstr + 2*i, "%2hhx", &out[i]);
    }
    return (int)(len / 2);
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "--pdu") != 0) {
        printf("Usage: %s --pdu <HEX_STRING>\n", argv[0]);
        return 1;
    }
    unsigned char pdu[MAX_PDU_LEN];
    int pdulen = hexstr_to_bytes(argv[2], pdu, MAX_PDU_LEN);
    if (pdulen < 0) {
        printf("Invalid PDU hex string.\n");
        return 1;
    }

    SMS_PDU *sms = sms_pdu_create(pdu, pdulen);
    if (!sms) {
        printf("Failed to parse PDU.\n");
        return 1;
    }
    sms_pdu_print(sms);
    sms_pdu_destroy(sms);
    return 0;
}
