// Copyright (c) 2021 The Globe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_WALLET_TEST_UTIL_H
#define GLOBE_WALLET_TEST_UTIL_H

#include <memory>

class ArgsManager;
class CChain;
class CKey;
namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, ArgsManager& args, const CKey& key);
} // namespace wallet

#endif // GLOBE_WALLET_TEST_UTIL_H
