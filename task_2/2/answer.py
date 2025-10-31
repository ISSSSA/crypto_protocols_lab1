from hashlib import shake_256

PRIME = 257
PRIME_FACTORS = [2]
INITIAL_HASH = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
BLOCK_SIZE = 8


class HashCollisionFinder:

    def __init__(self, prime: int = PRIME, prime_factors: list[int] = PRIME_FACTORS,
                 initial_hash: bytes = INITIAL_HASH):
        self.prime = prime
        self.prime_factors = prime_factors
        self.initial_hash = initial_hash
        self._precomputed_l_values = None

    def custom_hash(self, message: bytes) -> bytes:
        padding_length = (-len(message)) % BLOCK_SIZE
        padded_message = message + b"\x00" * padding_length

        current_hash = self.initial_hash

        for i in range(0, len(padded_message), BLOCK_SIZE):
            chunk = padded_message[i:i + BLOCK_SIZE]

            generators = [self.__hash_to_generator(byte) for byte in chunk]

            l_values = [pow(gen, byte_val, self.prime) - 1
                        for gen, byte_val in zip(generators, chunk)]

            current_hash = bytes(h_byte ^ l_byte
                                 for h_byte, l_byte in zip(current_hash, l_values))

        return current_hash

    def find_collision_pair(self) -> tuple[bytes, bytes]:
        l_values = self.__precompute_l_values()

        value_to_bytes = {}
        for byte_val, l_val in enumerate(l_values):
            value_to_bytes.setdefault(l_val, []).append(byte_val)

        collision_pairs = []

        for position in range(BLOCK_SIZE):
            target = self.initial_hash[position]
            found_pair = None

            for byte_a in range(256):
                needed_value = target ^ l_values[byte_a]
                if needed_value in value_to_bytes:
                    byte_b = value_to_bytes[needed_value][0]
                    found_pair = (byte_a, byte_b)
                    break

            if not found_pair:
                raise RuntimeError(f"No collision pair found for position {position}")

            collision_pairs.append(found_pair)

        block1 = bytes(pair[0] for pair in collision_pairs)
        block2 = bytes(pair[1] for pair in collision_pairs)

        return block1, block2

    def __hash_to_generator(self, message: int) -> int:
        current = message
        hasher = shake_256()
        generator_length = (self.prime.bit_length() + 7) // 8

        while True:
            hex_str = format(current, 'x')
            if len(hex_str) % 2 == 1:
                hex_str = '0' + hex_str

            hasher.update(bytes.fromhex(hex_str))
            current = int(hasher.hexdigest(generator_length), 16) % self.prime

            if self.__is_generator(current):
                return current

    def __is_generator(self, candidate: int) -> bool:
        if candidate in (0, 1):
            return False

        for factor in self.prime_factors:
            if pow(candidate, (self.prime - 1) // factor, self.prime) == 1:
                return False
        return True

    def __precompute_l_values(self) -> list[int]:
        if self._precomputed_l_values is None:
            self._precomputed_l_values = []
            for byte_value in range(256):
                generator = self.__hash_to_generator(byte_value)
                l_value = pow(generator, byte_value, self.prime) - 1
                self._precomputed_l_values.append(l_value)
        return self._precomputed_l_values


def main():
    finder = HashCollisionFinder()

    block1, block2 = finder.find_collision_pair()

    hash1 = finder.custom_hash(block1)
    hash2 = finder.custom_hash(block2)
    combined_hash = finder.custom_hash(block1 + block2)

    print("Демонстрация коллизии")
    print("=" * 50)
    print(f"Блок 1 (hex): {block1.hex()}")
    print(f"Блок 2 (hex): {block2.hex()}")
    print(f"Hash(Блок1):  {hash1.hex()}")
    print(f"Hash(Блок2):  {hash2.hex()}")
    print(f"Комбинированный хэш: {combined_hash.hex()}")

    print("\nXOR анализ:")
    for i, (b1, b2) in enumerate(zip(block1, block2)):
        print(f"  Позиция {i}: {hex(b1)} ⊕ {hex(b2)} = {hex(b1 ^ b2)}")


if __name__ == "__main__":
    main()
