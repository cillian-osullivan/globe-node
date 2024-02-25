// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Globe Core developers
// Copyright (c) 2017 The Globe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_RPC_RPCUTIL_H
#define GLOBE_RPC_RPCUTIL_H

#include <rpc/request.h>
#include <univalue.h>
#include <string>

void CallRPCVoid(std::string args, const std::any& context, std::string wallet="", bool force_wallet=false);
void CallRPCVoidRv(std::string args, const std::any& context, std::string wallet, bool *passed, UniValue *rv, bool force_wallet=false);
UniValue CallRPC(std::string args, const std::any& context, std::string wallet="", bool force_wallet=false);

void AddUri(JSONRPCRequest &request, std::string wallet, bool force_wallet=false);
void CallRPC(UniValue &rv, const JSONRPCRequest &request);

#endif // GLOBE_RPC_RPCUTIL_H

