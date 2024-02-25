#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Globe Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_globe import GlobeTestFramework
from test_framework.messages import (
    CBlockHeader,
    CBlock,
    msg_headers,
    msg_block,
    from_hex)


_compactblocks = __import__('p2p_compactblocks')
TestP2PConn = _compactblocks.TestP2PConn


class DoSTest(GlobeTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [ ['-debug=1', '-nosmsg', '-noacceptnonstdtxn', '-banscore=2000000', '-reservebalance=1000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        self.sync_all()

    def create_block_header(self, node, hashPrevBlock, hashMerkleRoot, target_block_hash):
        target_block = node.getblock(target_block_hash, 2)
        block = CBlockHeader(is_part=True)
        block.nTime = target_block['time']
        block.hashPrevBlock = hashPrevBlock
        block.nVersion = target_block['version']
        block.nBits = int(target_block['bits'], 16) # Will break after a difficulty adjustment...
        block.hashMerkleRoot = hashMerkleRoot
        block.hashWitnessMerkleRoot = 0
        #block.vchBlockSig = b"x" * 1024
        #block.hashMerkleRoot = block.calc_merkle_root()
        block.calc_sha256()
        return block

    def get_block_header(self, node, target_block_hash):
        target_block = node.getblock(target_block_hash, 2)
        block = CBlockHeader(is_part=True)
        block.nTime = target_block['time']
        block.hashPrevBlock = int(target_block['previousblockhash'], 16)
        block.nVersion = target_block['version']
        block.nBits = int(target_block['bits'], 16)
        block.hashMerkleRoot = int(target_block['merkleroot'], 16)
        block.hashWitnessMerkleRoot = int(target_block['witnessmerkleroot'], 16)
        block.calc_sha256()
        return block

    def run_test(self):

        check_blockindex_decay = True

        dos_nodes = 1  # or self.num_nodes
        log_path = self.options.tmpdir + '/node0/regtest/debug.log'

        nodes = self.nodes
        self.connect_nodes(0, 1)

        p2p_conns = []
        for i in range(dos_nodes):
            p2p_conns.append(self.nodes[i].add_p2p_connection(TestP2PConn()))

        nodes[0].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[0].getnewextaddress('lblExtTest')
        nodes[0].rescanblockchain()

        self.log.info('Generating blocks.')
        nodes[0].walletsettings('stakelimit', {'height':20})
        nodes[0].reservebalance(False)

        self.wait_for_height(nodes[0], 20, 2000)

        self.log.info('Syncing nodes.')
        for i in range(dos_nodes):
            self.nodes[i].p2ps[0].wait_for_verack()

        MAX_HEADERS = 10
        ITERATIONS = 200

        block_count = nodes[0].getblockcount()
        pastBlockHash = nodes[0].getblockhash(block_count - MAX_HEADERS - 1)

        # In each iteration, send a `headers` message with the maximum number of entries
        self.log.info('Initial blockindexsize: %d\n' % (nodes[0].getblockchaininfo()['blockindexsize']))
        self.log.info('Generating lots of headers with no stake\n')
        sent = 0
        for i in range(ITERATIONS):
            if i % 25 == 0:
                self.log.info('Iteration %d of %d sent, %d headers' % (i, ITERATIONS, MAX_HEADERS))
            prevBlockHash = int(pastBlockHash, 16)
            blocks = []
            for b in range(MAX_HEADERS):
                target_block_hash = nodes[0].getblockhash(block_count - MAX_HEADERS + b)
                block = self.create_block_header(nodes[0], hashPrevBlock=prevBlockHash, hashMerkleRoot=i, target_block_hash=target_block_hash)
                prevBlockHash = int(block.hash, 16)
                blocks.append(block)

            msg = msg_headers()
            msg.headers.extend(blocks)
            sent += len(blocks)
            # time.sleep(0.2)
            for i in range(dos_nodes):
                p2p_conns[i].send_message(msg)

        time.sleep(2)
        self.log.info('\nChecking how many headers were stored')
        self.log.info('Number of headers sent: %d' % (sent))
        self.log.info('blockindexsize: %d' % (nodes[0].getblockchaininfo()['blockindexsize']))

        self.log.info('Reading log file: ' + log_path)
        found_error_line = False
        found_misbehave_line = False
        with open(log_path, 'r', encoding='utf8') as fp:
            for line in fp:
                if not found_error_line and line.find('ERROR: AcceptBlockHeader: DoS limits') > -1:
                    found_error_line = True
                    self.log.info('Found line in log: ' + line)
                if not found_misbehave_line and line.find('): invalid header received') > -1:
                    found_misbehave_line = True
                    self.log.info('Found line in log: ' + line)
                if found_error_line and found_misbehave_line:
                    break
        assert (found_error_line)
        assert (found_misbehave_line)

        peer_info = nodes[0].getpeerinfo()
        assert (peer_info[1]['loose_headers'] >= 200)
        assert (peer_info[1]['banscore'] > 100)

        # Verify node under DOS isn't forwarding bad headers
        peer_info1 = nodes[1].getpeerinfo()
        assert (peer_info1[0]['loose_headers'] == 0)
        assert (peer_info1[0]['banscore'] == 0)

        if check_blockindex_decay:
            self.log.info('Waiting for unfilled headers to decay')
            for i in range(10):
                time.sleep(20)
                index_size = nodes[0].getblockchaininfo()['blockindexsize']
                self.log.info('waiting %d, blockindexsize: %d' % (i, index_size))
                if index_size <= 21:
                    break
            assert (nodes[0].getblockchaininfo()['blockindexsize'] == 21)

            self.log.info('Reading log file: ' + log_path)
            found_misbehave_line = False
            with open(log_path, 'r', encoding='utf8') as fp:
                for line in fp:
                    if line.find('Block not received') > -1:
                        found_misbehave_line = True
                        self.log.info('Found line in log: ' + line)
                        break
            assert (found_misbehave_line)

            self.log.info('Replace headers for next test')
            self.log.info('Initial blockindexsize: %d\n' % (nodes[0].getblockchaininfo()['blockindexsize']))
            self.log.info('Generating lots of headers with no stake\n')
            sent = 0
            for i in range(ITERATIONS):
                if i % 25 == 0:
                    self.log.info('Iteration %d of %d sent, %d headers' % (i, ITERATIONS, MAX_HEADERS))
                prevBlockHash = int(pastBlockHash, 16)
                blocks = []
                for b in range(MAX_HEADERS):
                    target_block_hash = nodes[0].getblockhash(block_count - MAX_HEADERS + b)
                    block = self.create_block_header(nodes[0], hashPrevBlock=prevBlockHash, hashMerkleRoot=i, target_block_hash=target_block_hash)
                    prevBlockHash = int(block.hash, 16)
                    blocks.append(block)

                msg = msg_headers()
                msg.headers.extend(blocks)
                sent += len(blocks)
                # time.sleep(0.2)
                for i in range(dos_nodes):
                    p2p_conns[i].send_message(msg)

            self.log.info('Number of headers sent: %d' % (sent))
            self.log.info('blockindexsize: %d' % (nodes[0].getblockchaininfo()['blockindexsize']))

        self.log.info('Restart and check how many block headers were saved to disk')
        self.stop_node(0)
        self.start_node(0, self.extra_args[0] + ['-wallet=default_wallet',])
        time.sleep(2)
        self.connect_nodes(0, 1)

        self.log.info('After restart blockindexsize: %d' % (nodes[0].getblockchaininfo()['blockindexsize']))
        assert (nodes[0].getblockchaininfo()['blockindexsize'] == 21)

        self.log.info('Sending many duplicate headers\n\n')

        self.nodes[0].add_p2p_connection(p2p_conns[0], wait_for_verack=False)
        for i in range(dos_nodes):
            self.nodes[i].p2ps[0].wait_for_verack()

        self.log.info('Initial blockindexsize: %d\n' % (nodes[0].getblockchaininfo()['blockindexsize']))

        DUPLICATE_ITERATIONS = 3000
        target_block_hash = nodes[0].getblockhash(20)
        block = self.get_block_header(nodes[0], target_block_hash=target_block_hash)
        prevBlockHash = int(block.hash, 16)
        sent = 0
        for i in range(DUPLICATE_ITERATIONS):
            if i % 250 == 0:
                self.log.info('Iteration %d of %d, sent %d duplicate headers' % (i, DUPLICATE_ITERATIONS, sent))
            blocks = []
            blocks.append(block)

            msg = msg_headers()
            msg.headers.extend(blocks)
            sent += len(blocks)
            # time.sleep(0.2)
            for i in range(dos_nodes):
                p2p_conns[i].send_message(msg)

        time.sleep(2)

        self.log.info("blockindexsize: %d\n" % (nodes[0].getblockchaininfo()['blockindexsize']))

        self.log.info('Reading log file: ' + log_path)
        found_dos_line = False
        with open(log_path, 'r', encoding='utf8') as fp:
            for line in fp:
                if line.find('Too many duplicates') > -1:
                    found_dos_line = True
                    self.log.info('Found line in log: ' + line)
                    break
        assert (found_dos_line)

        self.log.info('Test that invalid coinstakes are detected in acceptblock')
        prev_block_hash = nodes[0].getbestblockhash()
        prev_block = nodes[0].getblock(prev_block_hash, 2)

        block_hex = nodes[0].getblock(prev_block_hash, 0)
        b = from_hex(CBlock(), block_hex)
        b.vtx[0].vin[0].prevout.hash = int(prev_block['tx'][0]['txid'], 16)
        b.vtx[0].vin[0].prevout.n = 1

        b.hashMerkleRoot = b.calc_merkle_root()
        b.rehash()
        # Without resigning shound raise bad-block-signature
        p2p_conns[0].send_message(msg_block(block=b))
        block_modified_hex = b.serialize(with_witness=True, with_pos_sig=True).hex()

        block_sig_addr = prev_block['tx'][0]['vout'][1]['scriptPubKey']['address']
        block_resigned_hex = nodes[0].rehashblock(block_modified_hex, block_sig_addr)
        b = from_hex(CBlock(), block_resigned_hex)
        b.rehash()
        p2p_conns[0].send_message(msg_block(block=b))

        time.sleep(2)

        self.log.info('Reading log file: ' + log_path)
        bad_sig_line = 0
        invalid_stake_line = 0
        with open(log_path, 'r', encoding='utf8') as fp:
            for line in fp:
                if line.find('AcceptBlock FAILED (bad-block-signature') > -1:
                    bad_sig_line += 1
                    self.log.info('Found line in log: ' + line)
                elif line.find('AcceptBlock FAILED (invalid-stake-depth') > -1:
                    invalid_stake_line += 1
                    self.log.info('Found line in log: ' + line)
        assert (bad_sig_line == 1)
        assert (invalid_stake_line == 1)


if __name__ == '__main__':
    DoSTest().main()
