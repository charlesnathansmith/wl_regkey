#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include "macros.h"
#include "lictypes.h"
#include "utils.h"
#include "hwid.h"
#include "wlcrypt.h"

const char wl_hash[] = "6l51f72mCF1ZCn93ifP1O2LmHYF8d4vrpF0Toi6IcMA84sl82SI6L11WgwmLyX3a57332a7l9O18tNauR38W7v92l4wCEJcW7wY1qeqbDwI12qhlfJhplGag6z445uSD766WS4NcTyZqQD9b31pXgZ";
const char hwid[]    = "1037-629A-920A-E7B5-711F-EB93-1331-253F";
const char name[]    = "John";
const char company[] = "Company";
const char custom[]  = "Custom";

size_t lic_calc_size(const char* name, const char* company, const char* custom, const char* hwid)
{
    // Fixed
    size_t size = sizeof(license_head) + sizeof(license_tail);

    // Variable
    size += strlen(name) + strlen(company) + strlen(custom) + strlen(hwid) + 3 + (3 * 8);   // + null-terminators + end markers

    return size;
}

size_t lic_build_core(const char* main_hash, const char* hwid, uint8_t* out, size_t out_size)
{
    if (out_size < sizeof(lic_core))
    {
        fputs("Output buffer too small to build core!", stderr);
        return 0;
    }

    license_head* lic = (license_head*) out;
    h_head* hash = (h_head*) main_hash;

    puts("Generating license core...\n");

    // Setup inner-most nested core of license

    //These hash values come from the sdk keygens but never seem to get validated
    lic->nested.tea.core.init_hash_1 = hash->init_hash_1_1 + hash->init_hash_1_2;
    lic->nested.tea.core.init_hash_2 = hash->init_hash_2_1 + hash->init_hash_2_2;

    printf("init_hash1: %.8x\n", lic->nested.tea.core.init_hash_1);
    printf("init_hash2: %.8x\n", lic->nested.tea.core.init_hash_2);

    // HWID hashing
    if (!hwid)
    {
        fputs("HWID required!", stderr);
        return 0;
    }

    // Generate HWID hash
    printf("HWID key: %.8x\n", hash->hwid_key);

    hash_hwid(hwid, lic->nested.tea.core.hwid_hash, hash->hwid_key);

    printf("HWID hash:");

    for (size_t i = 0; i < 9; i++)
        printf(" %.2x", lic->nested.tea.core.hwid_hash[i]);
    
    puts("\n");

    // Unused license feature details set to random numbers
    lic->nested.tea.core.num_days = rnd();
    lic->nested.tea.core.num_execs = rnd();
    lic->nested.tea.core.exp_date = rnd();
    lic->nested.tea.core.global_minutes = rnd();
    lic->nested.tea.core.country_id = rnd();
    lic->nested.tea.core.runtime = rnd();

    return sizeof(lic_core);
}

size_t lic_build_tea(const char* main_hash, const char* name, const char* company, const char* custom, const char* hwid, uint8_t* out, size_t out_size)
{
    if (out_size < sizeof(lic_tea))
    {
        fputs("Output buffer too small to build TEA layer!", stderr);
        return 0;
    }

    license_head* lic = (license_head*)out;
    h_head* hash = (h_head*)main_hash;

    puts("Generating license TEA encrypted layer...\n");

    // Xor/add encode inner core
    // We can actually just make the key 0 and not encode it at all if we want
    //lic->nested.tea.core_xor_key = 0;

    lic->nested.tea.core_xor_key = rnd();
    core_encrypt((uint8_t*) &lic->nested.tea.core, sizeof(lic_core), lic->nested.tea.core_xor_key);
    
    printf("xor/add key: %.4x\n", lic->nested.tea.core_xor_key);

    // License "features" (restrictions)
    constexpr uint16_t LF_NUMDAYS = 1;
    constexpr uint16_t LF_NUMEXECS = 2;
    constexpr uint16_t LF_EXPDATE = 4;
    constexpr uint16_t LF_HWID = 8;
    constexpr uint16_t LF_GLOBMINS = 0x10;
    constexpr uint16_t LF_RUNTIME = 0x20;
    constexpr uint16_t LF_COUNTRY = 0x40;

    // HWID seems to be the only one required by the protected program
    lic->nested.tea.lic_flags = LF_HWID;
    printf("lic_flags: %.8x\n", lic->nested.tea.lic_flags);

    // Unused random number
    lic->nested.tea.random = rnd();
    printf("unused rnd: %.8x\n", lic->nested.tea.random);

    // Strings checksum
    lic->nested.tea.str_checksum = str_checksum(hwid) + str_checksum(name) + str_checksum(company) + str_checksum(custom);
    printf("Strings checksum: %.8x\n\n", lic->nested.tea.str_checksum);

    // Checksum (calculated after xor/add encoding)
    // Calculated on entire buffer up to where the checksum goes
    size_t chksum_size = (size_t) &(lic->nested.tea.checksum) - (size_t) lic;
    lic->nested.tea.checksum = bin_checksum((uint8_t*)&lic->nested.tea.core, chksum_size);
    
    // Magic number - must be this
    lic->nested.tea.magic = 0xe2b27878;

    return sizeof(lic_tea);
}

size_t lic_tea_encryption(const char* main_hash, uint8_t* out, size_t out_size)
{
    if (out_size < sizeof(lic_tea))
    {
        fputs("Output buffer too small for TEA encryption!", stderr);
        return 0;
    }

    h_head* hash = (h_head*)main_hash;

    puts("TEA encrypting license...\n");

    uint32_t tea_key[4] = { hash->tea_key_1_1 + hash->tea_key_1_2,
                            hash->tea_key_2_1 + hash->tea_key_2_2,
                            hash->tea_key_3_1 + hash->tea_key_3_2,
                            hash->tea_key_4_1 + hash->tea_key_4_2 };

    printf("TEA keys:");

    for (size_t i = 0; i < 4; i++)
        printf(" %.8x", tea_key[i]);

    puts("\n");

    tea_encrypt((uint32_t*) out, sizeof(lic_tea), tea_key);

    return sizeof(lic_tea);
}

size_t lic_pw_encryption(const char* main_hash, uint8_t* out, size_t out_size)
{
    if (out_size < sizeof(lic_tea))
    {
        fputs("Output buffer too small for password encryption!", stderr);
        return 0;
    }

    h_head* hash = (h_head*)main_hash;

    puts("Password encrypting license...\n");

    char password[33];

    strncpy((char*) password, (char*)hash->password, 32);
    password[32] = '\0';

    printf("Password: %s\n\n", password);

    pw_encrypt((uint8_t*) out, sizeof(lic_tea), (uint8_t*) password);

    sizeof(lic_tea);
}

size_t lic_finish_head(const char* main_hash, const char* name, const char* company, const char* custom, const char* hwid, uint8_t* out, size_t out_size)
{
    if (out_size < sizeof(license_head))
    {
        fputs("Output buffer too small to finish building license header!", stderr);
        return 0;
    }

    license_head* lic = (license_head*) out;
    h_head* hash = (h_head*) main_hash;

    puts("Finishing license header...\n");

    // Final init_hash
    lic->nested.init_hash_3 = (hash->init_hash_3_ >> 16) + hash->init_hash_3_;
    printf("init_hash_3: %.8x\n", lic->nested.init_hash_3);

    // Same strings checksum as before
    // We could have filled this in earlier, but I'm trying to build everything in order here for clarity
    lic->nested.str_checksum = str_checksum(hwid) + str_checksum(name) + str_checksum(company) + str_checksum(custom);
    printf("Strings checksum: %.8x\n", lic->nested.tea.str_checksum);

    // Final header checksum
    lic->checksum = bin_checksum((uint8_t*) lic, sizeof(lic_nested));
    printf("Header checksum: %.8x\n\n", lic->checksum);

    // Header end markers
    lic->end_marker1 = 0xFFFFFFFF;
    lic->end_marker2 = 0xFFFFFFFF;

    return sizeof(license_head);
}

size_t lic_write_string(uint8_t* pos, const char* str, size_t len, bool end_marker)
{
    strncpy((char*) pos, str, len);

    if (end_marker)
    {
        pdword(pos + len)     = 0xffffffff;
        pdword(pos + len + 4) = 0xffffffff;
        len += 8;
    }

    return len;
}

size_t lic_registered_to(const char* name, const char* company, const char* custom, const char* hwid, uint8_t* out, size_t out_size)
{
    // The license can actually handle utf-16 strings if you write 0x214E552A right before them
    // The string checksums used above have to be calculated slightly differently though
    // It's not really interesting enough to bother implementing here
    // (you only see your registration info once the first time you use a valid license)
    // The hwid still has to be in ascii but gets an extra null-terminator when using utf-16

    if (!name || !company || !custom || !hwid)
    {
        fputs("All string fields are mandatory!", stderr);
        return 0;
    }

    size_t name_len = strlen(name) + 1;
    size_t company_len = strlen(company) + 1;
    size_t custom_len = strlen(custom) + 1;
    size_t hwid_len = strlen(hwid);     // Not null-terminated

    size_t total_written = name_len + company_len + custom_len + hwid_len + (3 * 8); // + end marker lengths

    if (out_size < sizeof(license_head) + total_written)
    {
        fputs("Output buffer too small for string writes!", stderr);
        return 0;
    }

    out += sizeof(license_head);
    out += lic_write_string(out, name, name_len, true);
    out += lic_write_string(out, company, company_len, true);
    out += lic_write_string(out, custom, custom_len, true);
    
    lic_write_string(out, hwid, hwid_len, false);    // Doesn't get a standard end marker

    return total_written;
}

void lic_build_tail(uint8_t* tail_start)
{
    // Finish filling out license tail
    // This is all boilerplater as far as we're concerned
    // The caller needs to verify the buffer size from tail_start,
    // as it gets really convoluted passing in values to check it inside of here

    puts("Bulding license tail...\n");

    license_tail *tail = (license_tail*) tail_start;

    // String section end markers
    tail->double_null = 0;
    tail->end_marker1 = tail->end_marker2 = 0xfffffffd;

    // More magic nummbers
    tail->magic1 = 0x83a9b0f1;
    tail->magic2 = 0x1C;

    // Random
    tail->random = rnd();

    // WL's keygen copies an uninitialized local variable into it
    // Generally ends up being 0
    tail->unknown1 = 0;

    // Net instances
    // How many computers on a network can run the software at the same time
    // Idk if it just spams your LAN or what but it doesn't sound good
    // 0 = unlimited
    tail->net_instances = 0;

    // License creation date, I think
    // Some programs won't load if this isn't something sensible
    tail->timestamp = 0x07E7011D;

    // Same as above
    // No idea what they intended with these, but they work fine as is
    tail->unknown2 = 0;

    tail->end_marker3 = tail->end_marker4 = 0xfffffffd;
    tail->end_marker5 = tail->end_marker6 = 0xfffffffe;
}

void lic_str_tail_encrypt(uint8_t* out)
{
    // Uses the first dword of the license as a key to encrypt the string and tail sections
    uint32_t shift = pdword(out);

    license_head* lic = (license_head*) out;
    uint8_t *pos = (uint8_t*) &(lic->end_marker1);

    // Run until just before license end markers
    while (!( (pdword(pos) == 0xfffffffe) && (pdword(pos + 4) == 0xfffffffe) ))
    {
        *pos ^= shift;
        *pos += (shift >> 8);
        shift = ror32(shift, 1);

        pos++;
    }
}

size_t lic_final_checksum(uint8_t* out)
{
    // Calculate final checksum

    uint8_t sum[4] = { 0 };
    uint32_t state = 0;
    uint8_t *pos = out;

    while (!((pdword(pos) == 0xfffffffe) && (pdword(pos + 4) == 0xfffffffe)))
    {
        switch (state % 4)
        {
            case 0:
                sum[0] += *pos;
                break;

            case 1:
                sum[1] += *pos;
                break;

            case 2:
                sum[2] ^= *pos;
                break;

            case 3:
                sum[3] ^= *pos;
                break;
        }

        pos++;
        state++;
    }

    uint32_t checksum = (sum[1] << 24) | (sum[0] << 16) | (sum[3] << 8) | sum[2];

    printf("checksum: %.8x\n", checksum);

    // Skip over the end markers and write the checksum to the license
    pos += 8;
    pdword(pos) = checksum;

    // Return total buffer size (one past end of checksum - start of license)
    return (pos + 4) - out;
}

void print_buffer(uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf(" %.2x", buf[i]);

    puts("\n");
}

int main()
{
    puts("WL auxiliary license generator\n");

    // Make sure HWID is formatted correctly
    char hwid_loc[64];

    memset(hwid_loc, 0, sizeof(hwid_loc));
    strncpy(hwid_loc, hwid, sizeof(hwid_loc) - 2); //Have to leave 2 nulls to mark end of string (for what?)

    // Capitalize HWID and look for invalid characters
    if (!sanitize_hwid(hwid_loc))
    {
        fputs("HWID in incorrect format!", stderr);
        return 0;
    }

    printf("HWID:\t\t%s\n", hwid);
    printf("Name:\t\t%s\n", name);
    printf("Company:\t%s\n", company);
    printf("Custom:\t\t%s\n\n", custom);

    // Create license buffer
    size_t total_size = lic_calc_size(name, company, custom, hwid_loc);
    
    uint8_t* out = new uint8_t[total_size];
    memset(out, 0, total_size);

    // Build license core
    uint32_t size = lic_build_core(wl_hash, hwid_loc, out, total_size);

    lic_core *head = (lic_core*) out;

    head->init_hash_1 = 0xaaaaaaaa;
    head->init_hash_1 = 0xbbbbbbbb;
    head->hwid_hash[7] = 0xcc;
    head->hwid_hash[8] = 0xdd;

    if (!size)
    {
        fputs("Error building core!", stderr);
        return 0;
    }

    puts("Generated core:");
    print_buffer(out, size);

    // TEA encrypted layer
    size = lic_build_tea(wl_hash, name, company, custom, hwid_loc, out, total_size);

    if (!size)
    {
        fputs("Error building TEA layer!", stderr);
        return 0;
    }

    puts("Generated TEA layer:");
    print_buffer(out, size);
    
    // TEA encryption
    size = lic_tea_encryption(wl_hash, out, total_size);

    if (!size)
    {
        fputs("Error during TEA encryption!", stderr);
        return 0;
    }

    puts("TEA encrypted license:");
    print_buffer(out, size);
    
    // Password encryption
    size = lic_pw_encryption(wl_hash, out, total_size);

    if (!size)
    {
        fputs("Error during password encryption!", stderr);
        return 0;
    }

    puts("Password encrypted license:");
    print_buffer(out, size);

    // Finish building license header
    size = lic_finish_head(wl_hash, name, company, custom, hwid_loc, out, total_size);

    if (!size)
    {
        fputs("Error finishing license header!", stderr);
        return 0;
    }

    puts("Full license header:");
    print_buffer(out, size);
    
    // Write license strings
    size_t str_size = lic_registered_to(name, company, custom, hwid_loc, out, total_size);
    
    if (!str_size)
    {
        fputs("Error writing license strings!", stderr);
        return 0;
    }

    puts("License with strings:");
    print_buffer(out, sizeof(license_head) + str_size);

    // Build license tail
    uint8_t *lic_tail = out + sizeof(license_head) + str_size;

    lic_build_tail(lic_tail);

    puts("License with tail:");
    print_buffer(out, sizeof(license_head) + str_size + sizeof(license_tail));
    
    // License string and tail encryption
    lic_str_tail_encrypt(out);

    puts("License after string and tail encryption:");
    print_buffer(out, sizeof(license_head) + str_size + sizeof(license_tail));
    
    // Calculate final checksum
    size = lic_final_checksum(out);

    printf("Final buffer size: %.8x\n", size);

    puts("Final license before rsa:");
    print_buffer(out, size);

    delete[] out;
    return 0;
}

