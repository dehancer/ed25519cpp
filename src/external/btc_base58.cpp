//
// Created by denn on 2019-01-29.
//

// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "btc_base58.hpp"

#include <algorithm>
#include <assert.h>
#include <string.h>
#include <iomanip>
#include <iostream>


/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

namespace ed25519::base58 {


    string BinToHex(const vector<unsigned char> &data) {
        // note: optimize
        string convert;
        convert.reserve(data.size() * 2 + 2);
        std::stringstream s(convert);
        s << std::hex;
        for (size_t i = 0; i < data.size(); i++) {
            s << std::setw(2) << std::setfill('0') << (unsigned int) data[i];
        }
        return s.str();
    }

    bool HexToBin(const string &hexString, vector<unsigned char> &data, string &errorDescription) {
        // code 255 means error
        static unsigned char sDecLookupTable[] =
                {
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, // 0123456789
                        255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, //  ABCDEF
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //
                        255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, //  abcdef
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
                };

        errorDescription = "";
        data.clear();

        if ((hexString.size() & 1) != 0) {
            errorDescription = StringFormat("string with odd size: %zu bytes", hexString.size());
            return false;
        }

        size_t binarySize = hexString.size() >> 1; // /2

        data.resize(binarySize);

        for (size_t i = 0, j = 0; i < binarySize; i++, j += 2) {
            unsigned char h1 = hexString[j];
            unsigned char h0 = hexString[j + 1];
            //
            unsigned char c1 = sDecLookupTable[h1];
            unsigned char c0 = sDecLookupTable[h0];
            // check for errors
            if (c1 == 255 || c0 == 255) {
                errorDescription = StringFormat("bad %u hex symbol '%c%c'", i, h1, h0);
                return false;
            }
            data[i] = (c1 << 4) | c0;
        }

        return true;
    }

    bool HexStringToUchar(const string &hexString, unsigned char &value) {
        if (hexString.empty()) {
            return false;
        }

        string s = hexString;

        if (s.size() > 2 && s[0] == '0' && s[1] == 'x') {
            s = hexString.substr(2);
        }

        if (s.size() > (sizeof(unsigned char) * 2)) {
            return false;
        }

        unsigned int v = 0;
        std::stringstream ss;
        ss << std::hex << s;
        ss >> v;

        // check that all symbols are processed e.g. 0xfz -> error
        if (ss.fail() || !ss.eof()) {
            return false;
        }

        if (v > static_cast<unsigned int>(std::numeric_limits<unsigned char>::max())) {
            return false;
        }

        value = static_cast<unsigned char>(v);

        return true;
    }

    uint_least32_t crc32(unsigned char *buf, size_t len) {
        uint_least32_t crc_table[256] = {};
        uint_least32_t crc = {};

        for (int i = 0; i < 256; i++) {
            crc = i;
            for (int j = 0; j < 8; j++) {
                crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
            }
            crc_table[i] = crc;
        }

        crc = 0xFFFFFFFFUL;
        while (len--) {
            crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFUL;
    }

    bool DecodeBase58(const char *psz, vector<unsigned char> &vch) {
        // Skip leading spaces.
        while (*psz && isspace(*psz))
            psz++;
        // Skip and count leading '1's.
        int zeroes = 0;
        int length = 0;
        while (*psz == '1') {
            zeroes++;
            psz++;
        }
        // Allocate enough space in big-endian base256 representation.
        int size = (int) strlen(psz) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
        std::vector<unsigned char> b256(size);
        // Process the characters.
        while (*psz && !isspace(*psz)) {
            // Decode base58 character
            const char *ch = strchr(pszBase58, *psz);
            if (ch == nullptr)
                return false;
            // Apply "b256 = b256 * 58 + ch".
            int carry = (int) (ch - pszBase58);
            int i = 0;
            for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin();
                 (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
                carry += 58 * (*it);
                *it = carry % 256;
                carry /= 256;
            }
            assert(carry == 0);
            length = i;
            psz++;
        }
        // Skip trailing spaces.
        while (isspace(*psz))
            psz++;
        if (*psz != 0)
            return false;
        // Skip leading zeroes in b256.
        std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
        while (it != b256.end() && *it == 0)
            it++;
        // Copy result into output vector.
        vch.reserve(zeroes + (b256.end() - it));
        vch.assign(zeroes, 0x00);
        while (it != b256.end())
            vch.push_back(*(it++));
        return true;
    }

    std::string EncodeBase58(const unsigned char *pbegin, const unsigned char *pend) {
        // Skip & count leading zeroes.
        int zeroes = 0;
        int length = 0;
        while (pbegin != pend && *pbegin == 0) {
            pbegin++;
            zeroes++;
        }
        // Allocate enough space in big-endian base58 representation.
        int size = (int) (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
        std::vector<unsigned char> b58(size);
        // Process the bytes.
        while (pbegin != pend) {
            int carry = *pbegin;
            int i = 0;
            // Apply "b58 = b58 * 256 + ch".
            for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin();
                 (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
                carry += 256 * (*it);
                *it = carry % 58;
                carry /= 58;
            }

            assert(carry == 0);
            length = i;
            pbegin++;
        }
        // Skip leading zeroes in base58 result.
        std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
        while (it != b58.end() && *it == 0)
            it++;
        // Translate the result into a string.
        std::string str;
        str.reserve(zeroes + (b58.end() - it));
        str.assign(zeroes, '1');
        while (it != b58.end()) {
            str += pszBase58[*(it++)];
        }

        return str;
    }

    string EncodeBase58(const vector<unsigned char> &vch) {
        return EncodeBase58(vch.data(), vch.data() + vch.size());
    }

    bool DecodeBase58(const string &str, vector<unsigned char> &vchRet) {
        return DecodeBase58(str.c_str(), vchRet);
    }

    string EncodeBase58Check(const vector<unsigned char> &vchIn) {
        // add 4-byte hash check to the end
        vector<unsigned char> vch(vchIn);

        // uint256 hash = Hash(vch.begin(), vch.end());
        // vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);

        uint_least32_t crc32_ = crc32(&vch[0], vch.size());
        // little endian
        vch.push_back(static_cast<unsigned char>(crc32_ & 0xff));
        vch.push_back(static_cast<unsigned char>((crc32_ >> 8) & 0xff));
        vch.push_back(static_cast<unsigned char>((crc32_ >> 16) & 0xff));
        vch.push_back(static_cast<unsigned char>((crc32_ >> 24) & 0xff));

        return EncodeBase58(vch);
    }

    bool DecodeBase58Check(const char *psz, vector<unsigned char> &vchRet) {
        if (!DecodeBase58(psz, vchRet) || (vchRet.size() < 4)) {
            vchRet.clear();
            return false;
        }
        // re-calculate the checksum, ensure it matches the included 4-byte checksum
        // uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
        // if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        //     vchRet.clear();
        //     return false;
        // }
        size_t sz = vchRet.size();
        //
        uint_least32_t crc32_ = crc32(&vchRet[0], sz - 4);
        //
        if (static_cast<unsigned char>(crc32_ & 0xff) != vchRet[sz - 4] ||
            static_cast<unsigned char>((crc32_ >> 8) & 0xff) != vchRet[sz - 3] ||
            static_cast<unsigned char>((crc32_ >> 16) & 0xff) != vchRet[sz - 2] ||
            static_cast<unsigned char>((crc32_ >> 24) & 0xff) != vchRet[sz - 1]) {
            vchRet.clear();
            return false;
        }
        vchRet.resize(vchRet.size() - 4);

        return true;
    }

    bool DecodeBase58Check(const string &str, vector<unsigned char> &vchRet) {
        return DecodeBase58Check(str.c_str(), vchRet);
    }

    /// TODO:
    /// . make more effective
    bool Base58Check(const string &str) {
        vector<unsigned char> vchRet;
        return DecodeBase58Check(str.c_str(), vchRet);
    }
}