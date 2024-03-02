// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_CONSENSUS_CONSENSUS_H
#define GLOBE_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
extern unsigned int dgpMaxBlockSerSize;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
extern unsigned int dgpMaxBlockWeight;

extern unsigned int dgpMaxBlockSize; // globe



extern int64_t dgpMaxBlockSigOps;

extern unsigned int dgpMaxProtoMsgLength;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR_PART = 2;
static const int WITNESS_SCALE_FACTOR_GLB = 4;
extern unsigned int dgpMaxTxSigOps;

static const int MAX_TRANSACTION_BASE_SIZE = 1000000;
extern int WITNESS_SCALE_FACTOR;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

static const size_t MAX_DATA_OUTPUT_SIZE = 512;

void updateBlockSizeParams(unsigned int newBlockSize);

#endif // GLOBE_CONSENSUS_CONSENSUS_H
