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

#include "sms_pdu.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void print_bytes(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
}

static void print_bytes_with_newline(const uint8_t *data, size_t len) {
    print_bytes(data, len);
    printf("\n");
}

static SMS_PDU_Type determine_pdu_type(uint8_t tpdu_header) {
    uint8_t mti = tpdu_header & 0x03; // Extract bits 0-1 (MTI)
    return (SMS_PDU_Type)mti;
}

const char *sms_pdu_type_to_string(SMS_PDU_Type type) {
    switch (type) {
        case SMS_DELIVER: return "SMS-DELIVER";
        case SMS_SUBMIT: return "SMS-SUBMIT";
        case SMS_STATUS_REPORT: return "SMS-STATUS-REPORT";
        case SMS_RESERVED: return "RESERVED";
        default: return "UNKNOWN";
    }
}

void format_address(const uint8_t *addr_data, uint8_t addr_len, uint8_t toa, char *output, size_t output_size) {
    if (!addr_data || !output || output_size == 0) return;

    uint8_t type_of_number = (toa >> 4) & 0x07;

    if (type_of_number == 0x05) { // Alphanumeric
        // 7-bit packed GSM alphabet
        size_t output_idx = 0;
        uint8_t shift = 0;
        uint16_t carry = 0;

        for (int i = 0; i < (addr_len + 1) / 2 && output_idx < addr_len && output_idx < output_size - 1; i++) {
            uint8_t byte = addr_data[i];

            // Combine current byte with carry from previous byte
            uint16_t combined = carry | (byte << shift);

            // Extract 7-bit character
            uint8_t char_7bit = combined & 0x7F;

            // Convert from GSM 7-bit alphabet to ASCII (basic mapping)
            if (char_7bit >= 32 && char_7bit <= 126) {
                output[output_idx++] = char_7bit;
            }

            // Update shift and carry for next iteration
            shift++;
            carry = byte >> (8 - shift);

            // If we have enough bits for another character
            if (shift == 7) {
                if (carry >= 32 && carry <= 126 && output_idx < addr_len && output_idx < output_size - 1) {
                    output[output_idx++] = carry;
                }
                shift = 0;
                carry = 0;
            }
        }
        output[output_idx] = '\0';
    } else { // Numeric (phone number)
        size_t output_idx = 0;
        if (type_of_number == 0x01 && output_idx < output_size - 1) { // International
            output[output_idx++] = '+';
        }

        // Decode BCD digits (semi-octets)
        for (int i = 0; i < (addr_len + 1) / 2 && output_idx < output_size - 1; i++) {
            uint8_t byte = addr_data[i];

            // First digit (low nibble)
            uint8_t digit1 = byte & 0x0F;
            if (digit1 <= 9 && output_idx < output_size - 1) {
                output[output_idx++] = '0' + digit1;
            } else if (digit1 == 0x0A && output_idx < output_size - 1) {
                output[output_idx++] = '*';
            } else if (digit1 == 0x0B && output_idx < output_size - 1) {
                output[output_idx++] = '#';
            }

            // Second digit (high nibble) - only if we haven't reached addr_len
            if (i * 2 + 1 < addr_len) {
                uint8_t digit2 = (byte >> 4) & 0x0F;
                if (digit2 <= 9 && output_idx < output_size - 1) {
                    output[output_idx++] = '0' + digit2;
                } else if (digit2 == 0x0A && output_idx < output_size - 1) {
                    output[output_idx++] = '*';
                } else if (digit2 == 0x0B && output_idx < output_size - 1) {
                    output[output_idx++] = '#';
                }
            }
        }
        output[output_idx] = '\0';
    }
}

void format_timestamp(const uint8_t *ts_data, char *output, size_t output_size) {
    if (!ts_data || !output || output_size < 25) return; // Need at least 25 chars for full timestamp

    // Decode BCD semi-octets: YY MM DD HH MM SS TZ
    uint8_t year = ((ts_data[0] & 0x0F) * 10) + ((ts_data[0] >> 4) & 0x0F);
    uint8_t month = ((ts_data[1] & 0x0F) * 10) + ((ts_data[1] >> 4) & 0x0F);
    uint8_t day = ((ts_data[2] & 0x0F) * 10) + ((ts_data[2] >> 4) & 0x0F);
    uint8_t hour = ((ts_data[3] & 0x0F) * 10) + ((ts_data[3] >> 4) & 0x0F);
    uint8_t minute = ((ts_data[4] & 0x0F) * 10) + ((ts_data[4] >> 4) & 0x0F);
    uint8_t second = ((ts_data[5] & 0x0F) * 10) + ((ts_data[5] >> 4) & 0x0F);

    // Timezone is in quarters of an hour, with sign bit
    uint8_t tz_raw = ts_data[6];
    uint8_t tz_quarters = ((tz_raw & 0x0F) * 10) + ((tz_raw >> 4) & 0x07);
    int8_t tz_sign = (tz_raw & 0x08) ? -1 : 1; // bit 3 of high nibble is sign
    int16_t tz_hours = (tz_quarters * 15) / 60; // Convert quarters to hours
    int16_t tz_minutes = (tz_quarters * 15) % 60; // Remaining minutes

    // Format: YYYY-MM-DD HH:MM:SS +/-HHMM
    snprintf(output, output_size, "20%02d-%02d-%02d %02d:%02d:%02d %s%02d%02d",
             year, month, day, hour, minute, second,
             (tz_sign > 0) ? "+" : "-", tz_hours, tz_minutes);
}

const char *format_tp_pid(uint8_t tp_pid) {
    // Check bits 7,6 first
    uint8_t bits_7_6 = (tp_pid >> 6) & 0x03;

    switch (bits_7_6) {
        case 0x00: // bits 7,6 = 00
            if ((tp_pid & 0x20) == 0x00) {
                // Bit 5 = 0: no interworking, but SME-to-SME protocol
                if (tp_pid == 0x00) {
                    return "Short Message Type 0 (default)";
                }
                return "SME-to-SME protocol";
            } else {
                // Bit 5 = 1: telematic interworking
                uint8_t device_type = tp_pid & 0x1F;
                switch (device_type) {
                    case 0x00: return "Implicit - device type is specific to this SC";
                    case 0x01: return "Telex (or teletex reduced to telex format)";
                    case 0x02: return "Group 3 telefax";
                    case 0x03: return "Group 4 telefax";
                    case 0x04: return "Voice telephone (i.e. conversion to speech)";
                    case 0x05: return "ERMES (European Radio Messaging System)";
                    case 0x06: return "National Paging system (known to the SC)";
                    case 0x07: return "Videotex (T.100/T.101)";
                    case 0x08: return "Teletex, carrier unspecified";
                    case 0x09: return "Teletex, in PSPDN";
                    case 0x0A: return "Teletex, in CSPDN";
                    case 0x0B: return "Teletex, in analog PSTN";
                    case 0x0C: return "Teletex, in digital ISDN";
                    case 0x0D: return "UCI (Universal Computer Interface)";
                    case 0x0E:
                    case 0x0F: return "Reserved (telematic interworking)";
                    case 0x10: return "Message handling facility (known to the SC)";
                    case 0x11: return "Any public X.400-based message handling system";
                    case 0x12: return "Internet Electronic Mail";
                    case 0x13:
                    case 0x14:
                    case 0x15:
                    case 0x16:
                    case 0x17: return "Reserved (telematic interworking)";
                    case 0x18:
                    case 0x19:
                    case 0x1A:
                    case 0x1B:
                    case 0x1C:
                    case 0x1D:
                    case 0x1E: return "SC specific (mutual agreement between SME and SC)";
                    case 0x1F: return "GSM/UMTS mobile station";
                    default: return "Unknown telematic device";
                }
            }

        case 0x01: // bits 7,6 = 01
            {
                uint8_t message_type = tp_pid & 0x3F;
                switch (message_type) {
                    case 0x00: return "Short Message Type 0";
                    case 0x01: return "Replace Short Message Type 1";
                    case 0x02: return "Replace Short Message Type 2";
                    case 0x03: return "Replace Short Message Type 3";
                    case 0x04: return "Replace Short Message Type 4";
                    case 0x05: return "Replace Short Message Type 5";
                    case 0x06: return "Replace Short Message Type 6";
                    case 0x07: return "Replace Short Message Type 7";
                    case 0x08: return "Device Triggering Short Message";
                    case 0x1E: return "Enhanced Message Service (Obsolete)";
                    case 0x1F: return "Return Call Message";
                    case 0x3C: return "ANSI-136 R-DATA";
                    case 0x3D: return "ME Data download";
                    case 0x3E: return "ME De-personalization Short Message";
                    case 0x3F: return "(U)SIM Data download";
                    default:
                        if (message_type >= 0x09 && message_type <= 0x1D) {
                            return "Reserved";
                        } else if (message_type >= 0x20 && message_type <= 0x3B) {
                            return "Reserved";
                        }
                        return "Unknown message type";
                }
            }
        case 0x02: // bits 7,6 = 10
            return "Reserved";

        case 0x03: // bits 7,6 = 11
            return "SC specific use";

        default:
            return "Unknown/Reserved";
    }
}

static size_t parse_sms_deliver(SMS_PDU *pdu, const uint8_t *pdu_bytes, size_t pdu_len, size_t idx) {
    // Extract TP-MMS from bit 2 of TPDU header
    pdu->tp_mms = (pdu->tpdu_header & 0x04) ? 0 : 1; // MMS=0 means more messages, MMS=1 means no more messages

    // Originating Address Length
    pdu->addr_len = pdu_bytes[idx++];
    // Type-of-Originating-Address
    pdu->toa = pdu_bytes[idx++];
    // Originating Address (semi-octets, rounded up)
    size_t addr_bytes = (pdu->addr_len + 1) / 2;
    memcpy(pdu->originating_addr, &pdu_bytes[idx], addr_bytes);
    idx += addr_bytes;
    // TP-PID
    pdu->tp_pid = pdu_bytes[idx++];
    // TP-DCS
    pdu->tp_dcs = pdu_bytes[idx++];
    // TP-SCTS
    memcpy(pdu->tp_scts, &pdu_bytes[idx], 7);
    idx += 7;
    // UDL
    pdu->udl = pdu_bytes[idx++];

    // Check for UDH
    if (pdu->tpdu_header & 0x40) { // UDHI bit set
        uint8_t udhl = pdu_bytes[idx++];
        pdu->udh_len = udhl;
        memcpy(pdu->udh, &pdu_bytes[idx], udhl);
        idx += udhl;
    } else {
        pdu->udh_len = 0;
    }

    // User Data
    pdu->payload_len = (pdu_len > idx) ? (pdu_len - idx) : 0;
    memcpy(pdu->payload, &pdu_bytes[idx], pdu->payload_len);

    return idx + pdu->payload_len;
}

static size_t parse_sms_submit(SMS_PDU *pdu, const uint8_t *pdu_bytes, size_t pdu_len, size_t idx) {
    // TP-MR
    pdu->tp_mr = pdu_bytes[idx++];
    // Destination Address Length
    pdu->addr_len = pdu_bytes[idx++];
    // Type-of-Destination-Address
    pdu->toa = pdu_bytes[idx++];
    // Destination Address
    size_t addr_bytes = (pdu->addr_len + 1) / 2;
    memcpy(pdu->originating_addr, &pdu_bytes[idx], addr_bytes);
    idx += addr_bytes;
    // TP-PID
    pdu->tp_pid = pdu_bytes[idx++];
    // TP-DCS
    pdu->tp_dcs = pdu_bytes[idx++];
    // TP-VP (if present)
    uint8_t vpf = (pdu->tpdu_header >> 3) & 0x03;
    if (vpf == 0x02) idx += 1; // Relative format
    else if (vpf == 0x01 || vpf == 0x03) idx += 7; // Absolute/Enhanced format
    // UDL
    pdu->udl = pdu_bytes[idx++];

    // Check for UDH
    if (pdu->tpdu_header & 0x40) { // UDHI bit set
        uint8_t udhl = pdu_bytes[idx++];
        pdu->udh_len = udhl;
        memcpy(pdu->udh, &pdu_bytes[idx], udhl);
        idx += udhl;
    } else {
        pdu->udh_len = 0;
    }

    // User Data
    pdu->payload_len = (pdu_len > idx) ? (pdu_len - idx) : 0;
    memcpy(pdu->payload, &pdu_bytes[idx], pdu->payload_len);

    return idx + pdu->payload_len;
}

static size_t parse_sms_status_report(SMS_PDU *pdu, const uint8_t *pdu_bytes, size_t pdu_len, size_t idx) {
    // Extract TP-MMS from bit 2 of TPDU header
    pdu->tp_mms = (pdu->tpdu_header & 0x04) ? 0 : 1; // MMS=0 means more messages, MMS=1 means no more messages

    // TP-MR
    pdu->tp_mr = pdu_bytes[idx++];
    // TP-RA Length
    pdu->addr_len = pdu_bytes[idx++];
    // Type-of-RA
    pdu->toa = pdu_bytes[idx++];
    // TP-RA
    size_t addr_bytes = (pdu->addr_len + 1) / 2;
    memcpy(pdu->tp_ra, &pdu_bytes[idx], addr_bytes);
    idx += addr_bytes;
    // TP-SCTS
    memcpy(pdu->tp_scts, &pdu_bytes[idx], 7);
    idx += 7;
    // TP-DT
    memcpy(pdu->tp_dt, &pdu_bytes[idx], 7);
    idx += 7;
    // TP-ST
    pdu->tp_st = pdu_bytes[idx++];

    return idx;
}

SMS_PDU *sms_pdu_create(const uint8_t *pdu_bytes, size_t pdu_len) {
    if (!pdu_bytes || pdu_len < 2) return NULL;

    SMS_PDU *pdu = malloc(sizeof(SMS_PDU));
    if (!pdu) return NULL;

    // Initialize all fields to zero
    memset(pdu, 0, sizeof(SMS_PDU));

    size_t idx = 0;
    pdu->tpdu_header = pdu_bytes[idx++];
    pdu->pdu_type = determine_pdu_type(pdu->tpdu_header);

    switch (pdu->pdu_type) {
        case SMS_DELIVER:
            parse_sms_deliver(pdu, pdu_bytes, pdu_len, idx);
            break;
        case SMS_SUBMIT:
            parse_sms_submit(pdu, pdu_bytes, pdu_len, idx);
            break;
        case SMS_STATUS_REPORT:
            parse_sms_status_report(pdu, pdu_bytes, pdu_len, idx);
            break;
        default:
            // For unknown types, do basic parsing
            if (pdu_len > idx) {
                pdu->payload_len = pdu_len - idx;
                memcpy(pdu->payload, &pdu_bytes[idx], pdu->payload_len);
            }
            break;
    }

    return pdu;
}

void sms_pdu_destroy(SMS_PDU *pdu) {
    if (pdu) free(pdu);
}

void sms_pdu_print(const SMS_PDU *pdu) {
    if (!pdu) return;

    printf("PDU Type: %s\n", sms_pdu_type_to_string(pdu->pdu_type));
    printf("TPDU Header: %02X\n", pdu->tpdu_header);

    switch (pdu->pdu_type) {
        case SMS_DELIVER:
            printf("TP MMS (More Messages to Send): %s\n", pdu->tp_mms ? "No more messages" : "More messages to send");
            printf("Originating Address Length: %d\n", pdu->addr_len);
            printf("Type-of-Originating-Address: %02X\n", pdu->toa);
            char formatted_addr[50];
            format_address(pdu->originating_addr, pdu->addr_len, pdu->toa, formatted_addr, sizeof(formatted_addr));
            printf("Originating Address: %s (raw: ", formatted_addr);
            print_bytes(pdu->originating_addr, (pdu->addr_len + 1) / 2);
            printf(")\n");
            printf("TP PID: %02X (%s)\n", pdu->tp_pid, format_tp_pid(pdu->tp_pid));
            printf("TP DCS: %02X\n", pdu->tp_dcs);
            char formatted_scts[30];
            format_timestamp(pdu->tp_scts, formatted_scts, sizeof(formatted_scts));
            printf("TP SCTS: %s (raw: ", formatted_scts);
            print_bytes(pdu->tp_scts, 7);
            printf(")\n");
            printf("UDL: %d\n", pdu->udl);
            if (pdu->udh_len > 0) {
                printf("UDH (raw): ");
                print_bytes_with_newline(pdu->udh, pdu->udh_len);
            }
            printf("Message Payload (raw): ");
            print_bytes_with_newline(pdu->payload, pdu->payload_len);
            break;

        case SMS_SUBMIT:
            printf("TP Message Reference: %02X\n", pdu->tp_mr);
            printf("Destination Address Length: %d\n", pdu->addr_len);
            printf("Type-of-Destination-Address: %02X\n", pdu->toa);
            char formatted_dest[50];
            format_address(pdu->originating_addr, pdu->addr_len, pdu->toa, formatted_dest, sizeof(formatted_dest));
            printf("Destination Address: %s (raw: ", formatted_dest);
            print_bytes(pdu->originating_addr, (pdu->addr_len + 1) / 2);
            printf(")\n");
            printf("TP PID: %02X (%s)\n", pdu->tp_pid, format_tp_pid(pdu->tp_pid));
            printf("TP DCS: %02X\n", pdu->tp_dcs);
            printf("UDL: %d\n", pdu->udl);
            if (pdu->udh_len > 0) {
                printf("UDH (raw): ");
                print_bytes_with_newline(pdu->udh, pdu->udh_len);
            }
            printf("Message Payload (raw): ");
            print_bytes_with_newline(pdu->payload, pdu->payload_len);
            break;

        case SMS_STATUS_REPORT:
            printf("TP MMS (More Messages to Send): %s\n", pdu->tp_mms ? "No more messages" : "More messages to send");
            printf("TP Message Reference: %02X\n", pdu->tp_mr);
            printf("Recipient Address Length: %d\n", pdu->addr_len);
            printf("Type-of-Recipient-Address: %02X\n", pdu->toa);
            char formatted_recip[50];
            format_address(pdu->tp_ra, pdu->addr_len, pdu->toa, formatted_recip, sizeof(formatted_recip));
            printf("Recipient Address: %s (raw: ", formatted_recip);
            print_bytes(pdu->tp_ra, (pdu->addr_len + 1) / 2);
            printf(")\n");
            printf("TP SCTS: ");
            print_bytes_with_newline(pdu->tp_scts, 7);
            printf("TP DT: ");
            print_bytes_with_newline(pdu->tp_dt, 7);
            printf("TP Status: %02X\n", pdu->tp_st);
            break;

        default:
            printf("Unknown PDU type - raw payload: ");
            print_bytes_with_newline(pdu->payload, pdu->payload_len);
            break;
    }
}
