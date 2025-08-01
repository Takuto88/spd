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
#ifndef SMS_PDU_H
#define SMS_PDU_H

#include <stddef.h>
#include <stdint.h>

#define SMS_PDU_MAX_LEN 512

typedef enum {
    SMS_DELIVER = 0x00,
    SMS_DELIVER_REPORT = 0x00,  // Direction dependent
    SMS_SUBMIT = 0x01,
    SMS_SUBMIT_REPORT = 0x01,   // Direction dependent
    SMS_STATUS_REPORT = 0x02,
    SMS_COMMAND = 0x02,         // Direction dependent
    SMS_RESERVED = 0x03
} SMS_PDU_Type;

typedef struct {
    SMS_PDU_Type pdu_type;
    uint8_t tpdu_header;
    uint8_t addr_len;
    uint8_t toa;
    uint8_t originating_addr[20]; // max 20 digits
    uint8_t tp_pid;
    uint8_t tp_dcs;
    uint8_t tp_scts[7];
    uint8_t udl;
    uint8_t udh[20]; // max 20 bytes for UDH
    size_t udh_len;
    uint8_t payload[SMS_PDU_MAX_LEN];
    size_t payload_len;
    // Additional fields for different PDU types
    uint8_t tp_mr;     // Message Reference (SMS-SUBMIT, SMS-COMMAND)
    uint8_t tp_st;     // Status (SMS-STATUS-REPORT)
    uint8_t tp_dt[7];  // Discharge Time (SMS-STATUS-REPORT)
    uint8_t tp_ra[20]; // Recipient Address (SMS-STATUS-REPORT)
    uint8_t tp_ct;     // Command Type (SMS-COMMAND)
    uint8_t tp_mn;     // Message Number (SMS-COMMAND)
    uint8_t tp_cd[SMS_PDU_MAX_LEN]; // Command Data (SMS-COMMAND)
    size_t tp_cd_len;
    uint8_t tp_mms;    // More Messages to Send (SMS-DELIVER)
} SMS_PDU;

SMS_PDU *sms_pdu_create(const uint8_t *pdu_bytes, size_t pdu_len);
void sms_pdu_destroy(SMS_PDU *pdu);
void sms_pdu_print(const SMS_PDU *pdu);

#endif // SMS_PDU_H
