// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_POLICY_FEES_ARGS_H
#define GLOBE_POLICY_FEES_ARGS_H

#include <fs.h>

class ArgsManager;

/** @return The fee estimates data file path. */
fs::path FeeestPath(const ArgsManager& argsman);

#endif // GLOBE_POLICY_FEES_ARGS_H
