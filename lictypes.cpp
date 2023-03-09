/*********************************************
*
* WL File Key Demo
* Common types needed for license generation
*
*********************************************/

#include <stdint.h>
#include "lictypes.h"

// Capitalize ascii HWID and check for invalid chars
void reg_info::sanitize_hwid()
{
    for (char& c : hwid)
    {
        if ((c >= 'a') && (c <= 'f'))
        {
            c -= 0x20;      // Capitalize
            continue;
        }
        else if ((c != '-') && ((c < '0') || (c > '9')) && ((c < 'A') || (c > 'F')))
        {
            hwid.clear();   // Invalid char
            return;
        }
    }
}