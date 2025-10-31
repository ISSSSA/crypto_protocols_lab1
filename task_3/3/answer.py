from typing import Optional

cipher_text = 58103551549343228842179080321449360013591829087119069335322006885554051384510125469207375751567753676599969546359153452531457543384796275832055154709501075621624627371220003749689893923356667146750434314417082085
PREFIX = "present{"
SUFFIX = "}_just_for_test_1234567890abcef"

S_BOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
INV_S_BOX = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]

BLOCK_SIZE_BITS = 64
BLOCK_SIZE_BYTES = 8
NIBBLES_PER_BLOCK = 16
ROUNDS = 16


class PresentDecryptor:

    def __init__(self, cipher_text: int = cipher_text, prefix: str = PREFIX, suffix: str = SUFFIX):
        self.__cipher_text = cipher_text
        self.__prefix = prefix
        self.__suffix = suffix
        self.__min_length = len(prefix) + len(suffix)

    def int_to_blocks(self, x: int, block_size: int = BLOCK_SIZE_BITS) -> list[int]:
        if x == 0:
            return [0]

        blocks = []
        mask = (1 << block_size) - 1

        while x > 0:
            blocks.append(x & mask)
            x >>= block_size

        return blocks[::-1]

    def apply_sbox_to_block(self, block: int) -> int:
        result = 0
        for i in range(NIBBLES_PER_BLOCK):
            result <<= 4
            nibble = (block >> ((15 - i) * 4)) & 0xF
            result |= S_BOX[nibble]
        return result

    def apply_inv_sbox_to_block(self, block: int) -> int:
        result = 0
        for i in range(NIBBLES_PER_BLOCK):
            result <<= 4
            nibble = (block >> ((15 - i) * 4)) & 0xF
            result |= INV_S_BOX[nibble]
        return result

    def apply_rounds_to_nibble(self, value: int, key_nibble: int, rounds: int = ROUNDS) -> int:
        current_value = value
        for _ in range(rounds):
            current_value = S_BOX[(current_value ^ key_nibble) & 0xF]
        return current_value

    def decrypt(self, cipher_int: int, key: int) -> str:
        blocks = self.int_to_blocks(cipher_int, BLOCK_SIZE_BITS)
        decrypted_blocks = []

        for block in blocks:
            decrypted_block = block
            for _ in range(ROUNDS):
                decrypted_block = self.apply_inv_sbox_to_block(decrypted_block)
                decrypted_block ^= key
            decrypted_blocks.append(decrypted_block)

        result_int = 0
        for db in decrypted_blocks:
            result_int = (result_int << BLOCK_SIZE_BITS) | db

        if result_int == 0:
            return ""

        bytes_list = []
        temp = result_int
        while temp > 0:
            bytes_list.append(temp & 0xFF)
            temp >>= 8

        result_bytes = bytes(reversed(bytes_list))

        try:
            return result_bytes.decode('utf-8', errors='replace')
        except Exception:
            return str(result_bytes)

    def bytes_to_blocks(self, data: bytes) -> list[int]:
        if len(data) % BLOCK_SIZE_BYTES != 0:
            raise ValueError(f"Длина данных должна быть кратна {BLOCK_SIZE_BYTES}")

        blocks = []
        for i in range(0, len(data), BLOCK_SIZE_BYTES):
            block_value = 0
            for j in range(BLOCK_SIZE_BYTES):
                block_value = (block_value << 8) | data[i + j]
            blocks.append(block_value)

        return blocks

    def extract_nibbles_from_block(self, block: int) -> list[int]:
        nibbles = []
        for i in range(NIBBLES_PER_BLOCK):
            nibble = (block >> ((15 - i) * 4)) & 0xF
            nibbles.append(nibble)
        return nibbles

    def extract_nibbles_from_bytes(self, data: bytes) -> list[list[int]]:
        nibbles_list = []
        for byte in data:
            nibbles_list.append((byte >> 4) & 0xF)
            nibbles_list.append(byte & 0xF)
        return nibbles_list

    def find_key_from_known_plaintext(self, cipher_blocks: list[int],
                                      plain_bytes: bytes,
                                      known_mask: list[bool]) -> dict[int, list[int]]:
        num_blocks = len(cipher_blocks)

        plain_nibbles = []
        for block_idx in range(num_blocks):
            block_bytes = plain_bytes[block_idx * BLOCK_SIZE_BYTES:(block_idx + 1) * BLOCK_SIZE_BYTES]
            plain_nibbles.append(self.extract_nibbles_from_bytes(block_bytes))

        cipher_nibbles = [self.extract_nibbles_from_block(block) for block in cipher_blocks]

        pairs_by_position = {pos: [] for pos in range(NIBBLES_PER_BLOCK)}

        for block_idx in range(num_blocks):
            for pos in range(NIBBLES_PER_BLOCK):
                byte_index = block_idx * BLOCK_SIZE_BYTES + (pos // 2)
                if not known_mask[byte_index]:
                    continue

                plain_nibble = plain_nibbles[block_idx][pos]
                cipher_nibble = cipher_nibbles[block_idx][pos]
                pairs_by_position[pos].append((plain_nibble, cipher_nibble))

        possible_key_nibbles = {}
        for pos in range(NIBBLES_PER_BLOCK):
            candidates = []
            for key_candidate in range(16):
                valid = True
                for plain_nibble, cipher_nibble in pairs_by_position[pos]:
                    if self.apply_rounds_to_nibble(plain_nibble, key_candidate) != cipher_nibble:
                        valid = False
                        break
                if valid:
                    candidates.append(key_candidate)
            possible_key_nibbles[pos] = candidates

        return possible_key_nibbles

    def find_possible_solutions(self, max_additional_length: int = 200) -> list[tuple]:
        cipher_blocks = self.int_to_blocks(self.__cipher_text, BLOCK_SIZE_BITS)
        num_blocks = len(cipher_blocks)
        print(f"Количество блоков шифротекста: {num_blocks}")

        solutions = []
        max_length = self.__min_length + max_additional_length

        for length in range(self.__min_length, max_length + 1):
            plain_text = bytearray(length)
            plain_text[:] = b'\x00' * length
            plain_text[:len(self.__prefix)] = self.__prefix.encode()
            plain_text[length - len(self.__suffix):] = self.__suffix.encode()

            padding_bytes = (-length % BLOCK_SIZE_BYTES)
            padded_bytes = bytes(plain_text) + b'\x00' * padding_bytes

            plain_blocks = self.bytes_to_blocks(padded_bytes)
            if len(plain_blocks) != num_blocks:
                continue

            known_mask = [False] * len(padded_bytes)
            for i in range(len(padded_bytes)):
                if i < len(self.__prefix) or i >= (length - len(self.__suffix)) and i < length:
                    known_mask[i] = True

            possible_nibbles = self.find_key_from_known_plaintext(
                cipher_blocks, padded_bytes, known_mask
            )

            all_positions_have_candidates = all(len(v) > 0 for v in possible_nibbles.values())
            all_positions_unique = all(len(v) == 1 for v in possible_nibbles.values())

            if all_positions_have_candidates:
                solutions.append((length, possible_nibbles, all_positions_unique, padded_bytes))

        return solutions

    def select_best_solution(self, solutions: list[tuple]) -> Optional[tuple]:
        if not solutions:
            return None

        for solution in solutions:
            length, possible_nibbles, is_unique, padded_bytes = solution
            if is_unique:
                return solution

        return solutions[0]

    def recover_key(self, possible_nibbles: dict[int, list[int]]) -> int:
        key = 0
        for pos in range(NIBBLES_PER_BLOCK):
            if possible_nibbles[pos]:
                key = (key << 4) | possible_nibbles[pos][0]
            else:
                key = (key << 4)
        return key

    def run_decryption(self) -> None:
        print("=== Дешифрование PRESENT ===")

        solutions = self.find_possible_solutions()

        if not solutions:
            print("Не найдено подходящей длины/ключа.")
            return

        chosen_solution = self.select_best_solution(solutions)
        if chosen_solution is None:
            print("Не удалось выбрать решение.")
            return

        length, possible_nibbles, is_unique, padded_bytes = chosen_solution

        print(f"\nВыбранная длина L = {length} (уникальные нибблы: {is_unique})")

        key = self.recover_key(possible_nibbles)
        print(f"Восстановленный ключ (hex): {hex(key)}")

        print("\nНибблы ключа (по позициям 0..15):")
        for pos in range(NIBBLES_PER_BLOCK):
            candidates = possible_nibbles[pos]
            status = "✓ уникальный" if len(candidates) == 1 else f"? варианты: {candidates}"
            print(f"  Позиция {pos:2d}: {candidates} - {status}")

        decrypted_text = self.decrypt(self.__cipher_text, key)

        print("\n" + "=" * 50)
        print("Результат дешифрования:")
        print("=" * 50)
        print(f"Полный текст: {repr(decrypted_text)}")
        print(f"\nТекст без паддинга: {decrypted_text.rstrip(chr(0))}")


def main():
    decryptor = PresentDecryptor()
    decryptor.run_decryption()


if __name__ == "__main__":
    main()
