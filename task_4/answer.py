from sage.all import *


class FiniteFieldElement:

    PRIME = 5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659

    def __init__(self, value: int):
        self.value = value % self.PRIME

    @classmethod
    def from_inverse_mod(cls, value: int, modulus: int) -> 'FiniteFieldElement':
        inverse_value = inverse_mod(value, modulus)
        return cls(inverse_value)

    def __add__(self, other) -> 'FiniteFieldElement':
        if isinstance(other, FiniteFieldElement):
            return FiniteFieldElement(self.value + other.value)
        return FiniteFieldElement(self.value + other)

    def __sub__(self, other) -> 'FiniteFieldElement':
        if isinstance(other, FiniteFieldElement):
            return FiniteFieldElement(self.value - other.value)
        return FiniteFieldElement(self.value - other)

    def __mul__(self, other) -> 'FiniteFieldElement':
        if isinstance(other, FiniteFieldElement):
            return FiniteFieldElement(self.value * other.value)
        return FiniteFieldElement(self.value * other)

    def __truediv__(self, other) -> 'FiniteFieldElement':
        if isinstance(other, FiniteFieldElement):
            return self * other.multiplicative_inverse()
        return self * FiniteFieldElement(other).multiplicative_inverse()

    def __pow__(self, exponent: int) -> 'FiniteFieldElement':
        return FiniteFieldElement(pow(self.value, exponent, self.PRIME))

    def __eq__(self, other) -> bool:
        if isinstance(other, FiniteFieldElement):
            return self.value == other.value
        return self.value == (other % self.PRIME)

    def __ne__(self, other) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return f"FiniteFieldElement({self.value})"

    def __str__(self) -> str:
        return str(self.value)

    def multiplicative_inverse(self) -> 'FiniteFieldElement':
        if self.value == 0:
            raise ZeroDivisionError("Деление на нулевой элемент поля")

        gcd, x, _ = xgcd(self.value, self.PRIME)
        if gcd != 1:
            raise ValueError("Элемент не имеет обратного в данном поле")

        return FiniteFieldElement(x % self.PRIME)

    @property
    def numeric_value(self) -> int:
        return self.value


class MessageDecoder:

    @staticmethod
    def integer_to_string(number: int) -> str:
        if number == 0:
            return ""

        bytes_list = []
        temp = number

        while temp > 0:
            bytes_list.append(temp % 256)
            temp //= 256

        return bytes(bytes_list[::-1]).decode('utf-8', errors='replace')

    @staticmethod
    def string_to_integer(text: str) -> int:
        result = 0
        for char in text:
            result = (result << 8) | ord(char)
        return result


class FlagDecryptor:
    def __init__(self, a_inverse_value: int, encrypted_flag: int):
        self.a_inverse_value = a_inverse_value
        self.encrypted_flag = encrypted_flag
        self._a_inverse_element = None
        self._encrypted_element = None

    @property
    def a_inverse_element(self) -> FiniteFieldElement:
        if self._a_inverse_element is None:
            self._a_inverse_element = FiniteFieldElement(self.a_inverse_value)
        return self._a_inverse_element

    @property
    def encrypted_element(self) -> FiniteFieldElement:
        if self._encrypted_element is None:
            self._encrypted_element = FiniteFieldElement(self.encrypted_flag)
        return self._encrypted_element

    def decrypt_flag(self) -> FiniteFieldElement:
        return self.a_inverse_element * self.encrypted_element

    def get_decrypted_flag_as_string(self) -> str:
        decrypted_element = self.decrypt_flag()
        return MessageDecoder.integer_to_string(decrypted_element.numeric_value)


def main():
    A_INVERSE_VALUE = inverse_mod(
        3861609276618432016585008955197680894231781668102737801124620595063578145495460645887453456681384927228329987676511383027128609303727578732157213550205707,
        5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659
    )

    ENCRYPTED_FLAG = 3479471321001953002423905256519406413433825037007458615881760254608455405051330733641789845641456600201659876448793958581563279176512153464624363125939454

    decryptor = FlagDecryptor(A_INVERSE_VALUE, ENCRYPTED_FLAG)

    try:
        decrypted_flag = decryptor.get_decrypted_flag_as_string()
        print("Дешифрованный флаг:", decrypted_flag)

        print("\nДополнительная информация:")
        print(f"Обратное значение A: {A_INVERSE_VALUE}")
        print(f"Зашифрованный флаг: {ENCRYPTED_FLAG}")
        print(f"Дешифрованное числовое значение: {decryptor.decrypt_flag().numeric_value}")

    except Exception as e:
        print(f"Ошибка при дешифровании: {e}")


if __name__ == "__main__":
    main()
