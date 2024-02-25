// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Globe Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBE_CONSENSUS_VALIDATION_H
#define GLOBE_CONSENSUS_VALIDATION_H

#include <string>
#include <version.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <consensus/params.h>

class PeerManager;
class ChainstateManager;
class Chainstate;
class SmsgManager;

/** Index marker for when no witness commitment is present in a coinbase transaction. */
static constexpr int NO_WITNESS_COMMITMENT{-1};

/** Minimum size of a witness commitment structure. Defined in BIP 141. **/
static constexpr size_t MINIMUM_WITNESS_COMMITMENT{38};

/** A "reason" why a transaction was invalid, suitable for determining whether the
  * provider of the transaction should be banned/ignored/disconnected/etc.
  */
enum class TxValidationResult {
    TX_RESULT_UNSET = 0,     //!< initial value. Tx has not yet been rejected
    TX_CONSENSUS,            //!< invalid by consensus rules
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    TX_RECENT_CONSENSUS_CHANGE,
    TX_INPUTS_NOT_STANDARD,   //!< inputs (covered by txid) failed policy rules
    TX_NOT_STANDARD,          //!< otherwise didn't meet our local policy rules
    TX_MISSING_INPUTS,        //!< transaction was missing some of its inputs
    TX_PREMATURE_SPEND,       //!< transaction spends a coinbase too early, or violates locktime/sequence locks
    /**
     * Transaction might have a witness prior to SegWit
     * activation, or witness may have been malleated (which includes
     * non-standard witnesses).
     */
    TX_WITNESS_MUTATED,
    /**
     * Transaction is missing a witness.
     */
    TX_WITNESS_STRIPPED,
    /**
     * Tx already in mempool or conflicts with a tx in the chain
     * (if it conflicts with another tx in mempool, we use MEMPOOL_POLICY as it failed to reach the RBF threshold)
     * Currently this is only used if the transaction already exists in the mempool or on chain.
     */
    TX_CONFLICT,
    TX_MEMPOOL_POLICY,        //!< violated mempool's fee/size/descendant/RBF/etc limits
    TX_NO_MEMPOOL,            //!< this node does not have a mempool so can't validate the transaction

    DOS_100,
    DOS_50,
    DOS_20,
    DOS_5,
    DOS_1,
};

/** A "reason" why a block was invalid, suitable for determining whether the
  * provider of the block should be banned/ignored/disconnected/etc.
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
enum class BlockValidationResult {
    BLOCK_RESULT_UNSET = 0,  //!< initial value. Block has not yet been rejected
    BLOCK_CONSENSUS,         //!< invalid by consensus rules (excluding any below reasons)
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    BLOCK_RECENT_CONSENSUS_CHANGE,
    BLOCK_CACHED_INVALID,    //!< this block was cached as being invalid and we didn't store the reason why
    BLOCK_INVALID_HEADER,    //!< invalid proof of work or time too old
    BLOCK_MUTATED,           //!< the block's data didn't match the data committed to by the PoW
    BLOCK_MISSING_PREV,      //!< We don't have the previous block the checked one is built on
    BLOCK_INVALID_PREV,      //!< A block this one builds on is invalid
    BLOCK_TIME_FUTURE,       //!< block timestamp was > 2 hours in the future (or our clock is bad)
    BLOCK_CHECKPOINT,        //!< the block failed to meet one of our checkpoints
    BLOCK_HEADER_LOW_WORK,   //!< the block header may be on a too-little-work chain

    DOS_100,
    DOS_50,
    DOS_20,
    DOS_5,
    DOS_1,
};


/** Template for capturing information about block/transaction validation. This is instantiated
 *  by TxValidationState and BlockValidationState for validation information on transactions
 *  and blocks respectively. */
template <typename Result>
class ValidationState
{
private:
    enum class ModeState {
        M_VALID,   //!< everything ok
        M_INVALID, //!< network rule violation (DoS value may be set)
        M_ERROR,   //!< run-time error
    } m_mode{ModeState::M_VALID};
    Result m_result{};
    std::string m_reject_reason;
    std::string m_debug_message;

public:
    bool Invalid(Result result,
                 const std::string& reject_reason = "",
                 const std::string& debug_message = "")
    {
        m_result = result;
        m_reject_reason = reject_reason;
        m_debug_message = debug_message;
        if (m_mode != ModeState::M_ERROR) m_mode = ModeState::M_INVALID;
        return false;
    }
    bool Error(const std::string& reject_reason)
    {
        if (m_mode == ModeState::M_VALID)
            m_reject_reason = reject_reason;
        m_mode = ModeState::M_ERROR;
        return false;
    }
    bool IsValid() const { return m_mode == ModeState::M_VALID; }
    bool IsInvalid() const { return m_mode == ModeState::M_INVALID; }
    bool IsError() const { return m_mode == ModeState::M_ERROR; }
    Result GetResult() const { return m_result; }
    std::string GetRejectReason() const { return m_reject_reason; }
    std::string GetDebugMessage() const { return m_debug_message; }

    std::string ToString() const
    {
        if (IsValid()) {
            return "Valid";
        }

        if (!m_debug_message.empty()) {
            return m_reject_reason + ", " + m_debug_message;
        }

        return m_reject_reason;
    }

    PeerManager *m_peerman{nullptr};
    SmsgManager *m_smsgman{nullptr};
    ChainstateManager *m_chainman{nullptr};
    Chainstate *m_chainstate{nullptr};
    int nodeId = -1;
    int nFlags = 0;
    bool fEnforceSmsgFees = false;
    bool fBulletproofsActive = false;
    bool rct_active = false;
    int m_spend_height = 0;
    bool m_globe_mode = false;
    bool m_skip_rangeproof = false;
    const Consensus::Params *m_consensus_params = nullptr;
    bool m_preserve_state = false; // Don't clear error during ActivateBestChain (debug)

    // TxValidationState
    int64_t m_time = 0;
    bool m_funds_smsg = false;
    bool m_has_anon_output = false;
    bool m_has_anon_input = false;
    bool m_spends_frozen_blinded = false;
    bool m_clamp_tx_version = false;
    bool m_exploit_fix_1 = false;
    bool m_exploit_fix_2 = false;
    bool m_in_block = false;
    bool m_check_equal_rct_txid = true;
    bool m_punish_for_duplicates = false;
    CAmount tx_balances[6] = {0};
    std::set<CCmpPubKey> m_setHaveKI;

    void SetStateInfo(int64_t time, int spend_height, const Consensus::Params& consensusParams, bool globe_mode, bool skip_rangeproof, bool in_block=false)
    {
        m_time = time;
        m_in_block = in_block;
        m_consensus_params = &consensusParams;
        fEnforceSmsgFees = time >= consensusParams.nPaidSmsgTime;
        fBulletproofsActive = time >= consensusParams.bulletproof_time;
        rct_active = time >= consensusParams.rct_time;
        if (spend_height > -1) {
            m_spend_height = spend_height; // Pass through connectblock->checkblock
        }
        m_globe_mode = globe_mode;
        m_skip_rangeproof = skip_rangeproof;

        m_clamp_tx_version = time >= consensusParams.clamp_tx_version_time;
        m_exploit_fix_1 = time >= consensusParams.exploit_fix_1_time;
        m_exploit_fix_2 = time >= consensusParams.exploit_fix_2_time;
        if (m_in_block && m_time < 1632177542) {
            m_check_equal_rct_txid = false;
        }
    }

    void CopyStateInfo(const ValidationState &state_from)
    {
        m_peerman = state_from.m_peerman;
        m_chainman = state_from.m_chainman;
        m_chainstate = state_from.m_chainstate;

        m_time = state_from.m_time;
        m_in_block = state_from.m_in_block;
        m_consensus_params = state_from.m_consensus_params;
        fEnforceSmsgFees = state_from.fEnforceSmsgFees;
        fBulletproofsActive = state_from.fBulletproofsActive;
        rct_active = state_from.rct_active;
        m_spend_height = state_from.m_spend_height;

        m_globe_mode = state_from.m_globe_mode;
        m_skip_rangeproof = state_from.m_skip_rangeproof;

        m_clamp_tx_version = state_from.m_clamp_tx_version;
        m_exploit_fix_1 = state_from.m_exploit_fix_1;
        m_exploit_fix_2 = state_from.m_exploit_fix_2;
        m_check_equal_rct_txid = state_from.m_check_equal_rct_txid;
        m_punish_for_duplicates = state_from.m_punish_for_duplicates;
    }
};

class TxValidationState : public ValidationState<TxValidationResult> {};
class BlockValidationState : public ValidationState<BlockValidationResult> {};

// These implement the weight = (stripped_size * 4) + witness_size formula,
// using only serialization with and without witness data. As witness_size
// is equal to total_size - stripped_size, this formula is identical to:
// weight = (stripped_size * 3) + total_size.
static inline int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(tx, PROTOCOL_VERSION);
}
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, PROTOCOL_VERSION);
}
static inline int64_t GetTransactionInputWeight(const CTxIn& txin)
{
    // scriptWitness size is added here because witnesses and txins are split up in segwit serialization.
    return ::GetSerializeSize(txin, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(txin, PROTOCOL_VERSION) + ::GetSerializeSize(txin.scriptWitness.stack, PROTOCOL_VERSION);
}

/** Compute at which vout of the block's coinbase transaction the witness commitment occurs, or -1 if not found */
inline int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = NO_WITNESS_COMMITMENT;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            const CTxOut& vout = block.vtx[0]->vout[o];
            if (vout.scriptPubKey.size() >= MINIMUM_WITNESS_COMMITMENT &&
                vout.scriptPubKey[0] == OP_RETURN &&
                vout.scriptPubKey[1] == 0x24 &&
                vout.scriptPubKey[2] == 0xaa &&
                vout.scriptPubKey[3] == 0x21 &&
                vout.scriptPubKey[4] == 0xa9 &&
                vout.scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}


#endif // GLOBE_CONSENSUS_VALIDATION_H
