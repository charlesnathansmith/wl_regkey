#pragma once

/*********************************************
*
* WL File Key Demo
* Common types needed for license generation
*
*********************************************/

#include <stdint.h>
#include <string>
#include "hwid.h"

// License "features" (restrictions)
constexpr uint16_t LF_NUMDAYS = 1;
constexpr uint16_t LF_NUMEXECS = 2;
constexpr uint16_t LF_EXPDATE = 4;
constexpr uint16_t LF_HWID = 8;
constexpr uint16_t LF_GLOBMINS = 0x10;
constexpr uint16_t LF_RUNTIME = 0x20;
constexpr uint16_t LF_COUNTRY = 0x40;

// Registration information
struct reg_info
{
    std::string name, company, custom, hwid;

    reg_info(std::string name, std::string company, std::string custom, std::string (hwid))
        : name(name), company(company), custom(custom), hwid(hwid) { sanitize_hwid(); }

    void sanitize_hwid();
};

#pragma pack(push, 1)

// License format structures
struct lic_core
{
    uint32_t   hash_1;		    // Calculated from main_hash
    uint8_t    num_days;		// Num days after registration license is valid
    uint8_t    num_execs;		// Num times program can be run with this license
    uint32_t   exp_date;		// Date this license expires
    uint32_t   global_minutes;	// Total mins a program can run with this license
    uint32_t   country_id;		// Country ID per Windows Language settings
    uint32_t   runtime;		    // Per-run max mins program can be open
    uint32_t   hash_2;		    // Calculated from main_hash
    hwid_hash  hwid_hash;		// HWID verification
};

struct lic_tea
{
    lic_core core;			// The above structure
    uint16_t core_xor_key;	// Xor/add key used to encrypt core
    uint16_t lic_flags;		// Dictate which license restrictions to enforce
    uint32_t random;		// Any random number
    uint16_t str_checksum;	// Registration strings checksum
    uint16_t checksum;		// Checksum on the buffer up to here after core encrypt
    uint32_t magic;		    // Must be 0xe2b27878
};

struct license_head
{
    lic_tea  tea;			// The above structure
    uint16_t hash_3;		// Calculated from main_hash
    uint16_t str_checksum;	// The same registration strings checksum as in lic_tea
    uint16_t checksum;		// Checksum on up to here after encryptions
};

struct license_tail
{
    uint16_t double_null;       // Always 0x0000
    uint32_t beg_marker[2];     // Always 0xfffffffd, 0xfffffffd
    uint32_t magic[2];          // Always 0x83a9b0f1, 0x1C
    uint32_t random;            // Pick a number, any number

    uint32_t install_by;        // First license use must be before this date
    uint32_t net_instances;     // Total instances that may run on a network
    uint32_t creation_date;     // When the license was made
    uint32_t unknown;           // Probably used by SmartActivate licenses

    uint32_t end_marker[4];     // 0xfffffffd, 0xfffffffd, 0xfffffffe, 0xfffffffe
    uint32_t checksum;          // Final checksum on main body
};

#pragma pack(pop)
