// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_WALLET_RPCHDWALLET_H
#define GLOBE_WALLET_RPCHDWALLET_H

class CRPCCommand;
class CHDWallet;
class CRPCTable;

void EnsureWalletIsUnlocked(const CHDWallet *pwallet);

Span<const CRPCCommand> GetHDWalletRPCCommands();

void RegisterNonWalletRPCCommands(CRPCTable& t);

#endif // GLOBE_WALLET_RPCHDWALLET_H
