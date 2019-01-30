// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */
#ifndef ED25512__BITCOIN_BASE58_H
#define ED25512__BITCOIN_BASE58_H

#include "ed25519.hpp"
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <sstream>

using std::string;
using std::vector;
using std::array;

namespace ed25519::base58 {
/**
 * Encode a byte vector as a base58-encoded string
 */
    string EncodeBase58(const vector<unsigned char> &vch);


/**
 * Decode a base58-encoded string (str) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
    bool DecodeBase58Check(const string &str, vector<unsigned char> &vchRet);

    /**
 * Check base58-encoded string
 * @param str
 * @return true if it is right
 */
    bool Base58Check(const string &str);
}


#endif // ED25512__BITCOIN_BASE58_H
