import hashlib
import binascii
import struct
import os
import time
import sys
import argparse

def main():
    options = get_args()
    if options.algorithm != "SHA256":
        sys.exit("Error: Only SHA256 is supported in this version.")

    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print_block_info(options, hash_merkle_root)

    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)

def get_args():
    parser = argparse.ArgumentParser(description="Generate a genesis block with SHA256.")
    parser.add_argument("-t", "--time", type=int, default=int(time.time()),
                        help="The (Unix) time when the genesis block is created")
    parser.add_argument("-z", "--timestamp", type=str, default="TRRXITTE BTC - 31/Mar/2025",
                        help="The pszTimestamp found in the coinbase of the genesis block")
    parser.add_argument("-n", "--nonce", type=int, default=0,
                        help="The first value of the nonce to increment when searching the genesis hash")
    parser.add_argument("-a", "--algorithm", type=str, default="SHA256",
                        help="The PoW algorithm (only SHA256 supported)")
    parser.add_argument("-p", "--pubkey", type=str, default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
                        help="The pubkey found in the output script")
    parser.add_argument("-v", "--value", type=int, default=5000000000,
                        help="The value in coins for the output (e.g., 5000000000 for 50 coins)")
    parser.add_argument("-b", "--bits", type=int, default=0x1e0ffff0,
                        help="The target in compact representation")

    return parser.parse_args()

def create_input_script(psz_timestamp):
    psz_prefix = "4c" if len(psz_timestamp) > 76 else ""
    script_prefix = "04ffff001d0104" + psz_prefix + format(len(psz_timestamp), '02x')
    return binascii.unhexlify(script_prefix + psz_timestamp.encode('utf-8').hex())

def create_output_script(pubkey):
    script_len = "41"
    OP_CHECKSIG = "ac"
    return binascii.unhexlify(script_len + pubkey + OP_CHECKSIG)

def create_transaction(input_script, output_script, options):
    tx = (
        struct.pack("<I", 1) +          # version
        b"\x01" +                       # num_inputs
        b"\x00" * 32 +                  # prev_output
        struct.pack("<I", 0xFFFFFFFF) + # prev_out_idx
        struct.pack("B", len(input_script)) + # input_script_len
        input_script +                  # input_script
        struct.pack("<I", 0xFFFFFFFF) + # sequence
        b"\x01" +                       # num_outputs
        struct.pack("<q", options.value) + # out_value
        b"\x43" +                       # output_script_len
        output_script +                 # output_script
        struct.pack("<I", 0)            # locktime
    )
    return tx

def create_block_header(hash_merkle_root, time_val, bits, nonce):
    block_header = (
        struct.pack("<I", 1) +          # version
        b"\x00" * 32 +                  # hash_prev_block
        hash_merkle_root +              # hash_merkle_root
        struct.pack("<I", time_val) +   # time
        struct.pack("<I", bits) +       # bits
        struct.pack("<I", nonce)        # nonce
    )
    return block_header

def generate_hash(data_block, start_nonce, bits):
    print("Searching for genesis hash...")
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
        last_updated = calculate_hashrate(nonce, last_updated)
        if int(sha256_hash.hex(), 16) < target:
            return sha256_hash, nonce
        nonce += 1
        data_block = data_block[:-4] + struct.pack("<I", nonce)

def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(2**32 / hashrate / 3600, 1)
        sys.stdout.write(f"\r{hashrate} hash/s, estimate: {generation_time} h")
        sys.stdout.flush()
        return now
    return last_updated

def print_block_info(options, hash_merkle_root):
    print(f"algorithm: {options.algorithm}")
    print(f"merkle hash: {hash_merkle_root[::-1].hex()}")
    print(f"pszTimestamp: {options.timestamp}")
    print(f"pubkey: {options.pubkey}")
    print(f"time: {options.time}")
    print(f"bits: {hex(options.bits)}")

def announce_found_genesis(genesis_hash, nonce):
    print("genesis hash found!")
    print(f"nonce: {nonce}")
    print(f"genesis hash: {genesis_hash.hex()}")

if __name__ == "__main__":
    main()
