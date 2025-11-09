import gmpy2
from typing import Tuple


class RSACryptographer:
    def __init__(self, modulus: int, ciphertext: int, public_exponent: int = 65537):
        self.modulus = modulus
        self.ciphertext = ciphertext
        self.public_exponent = public_exponent
        self._prime_p = None
        self._prime_q = None
        self._private_key = None

    def _calculate_cube_root_approximation(self) -> int:
        return gmpy2.iroot(self.modulus, 3)[0]

    @staticmethod
    def _is_prime(number: int) -> bool:
        return gmpy2.is_prime(number)

    def _find_next_prime(self, start_number: int) -> int:
        candidate = int(start_number)
        if candidate % 2 == 0:
            candidate += 1

        while not self._is_prime(candidate):
            candidate += 2

        return candidate

    def _find_prime_factors(self) -> Tuple[int, int]:
        cube_root_approx = self._calculate_cube_root_approximation()
        prime_candidate = self._find_next_prime(cube_root_approx)

        if self.modulus % prime_candidate == 0:
            factor_p = prime_candidate
            factor_q = self.modulus // prime_candidate
            return factor_p, factor_q

        search_start = cube_root_approx - 100000
        prime_candidate = self._find_next_prime(search_start)

        while self.modulus % prime_candidate != 0:
            prime_candidate = self._find_next_prime(prime_candidate + 2)

        factor_p = prime_candidate
        factor_q = self.modulus // factor_p

        return factor_p, factor_q

    def factorize_modulus(self) -> Tuple[int, int]:
        if self._prime_p is None or self._prime_q is None:
            self._prime_p, self._prime_q = self._find_prime_factors()

        return self._prime_p, self._prime_q

    def _calculate_private_key(self) -> int:
        if self._prime_p is None or self._prime_q is None:
            self.factorize_modulus()

        euler_totient = (self._prime_p - 1) * (self._prime_q - 1)
        return gmpy2.invert(self.public_exponent, euler_totient)

    def get_private_key(self) -> int:
        if self._private_key is None:
            self._private_key = self._calculate_private_key()
        return self._private_key

    def decrypt_message(self) -> int:
        private_key = self.get_private_key()
        return pow(self.ciphertext, private_key, self.modulus)

    @staticmethod
    def convert_int_to_string(number: int) -> str:
        if number == 0:
            return ""

        bytes_list = []
        while number > 0:
            bytes_list.append(number & 0xFF)
            number >>= 8

        return bytes(bytes_list[::-1]).decode('latin-1')


class RSAAnalyzer:

    def __init__(self, cryptographer: RSACryptographer):
        self.cryptographer = cryptographer

    def analyze_and_decrypt(self) -> dict:
        p, q = self.cryptographer.factorize_modulus()
        decrypted_number = self.cryptographer.decrypt_message()
        decrypted_message = self.cryptographer.convert_int_to_string(decrypted_number)

        return {
            'prime_p': p,
            'prime_q': q,
            'decrypted_number': decrypted_number,
            'decrypted_message': decrypted_message,
            'modulus_bit_length': self.cryptographer.modulus.bit_length(),
            'verification': p * q == self.cryptographer.modulus
        }


def main():
    MODULUS = 3551461544640775896900024628658155911984133067110855611494602592007900618081284364265326994169132960500302314795501447332598035949607736652186223499178118139062274549376783752862916972594385324474195744041377878875718325061982763149629812611894904118986508664340788733364281628957567874539823321736784625840659758586477111613484396409247086492074595603529047017706657909567138662737065345793441877504075671076645145065495409403865946635751614875112674141532654635624405776173260357469512684289692512975610716651946489594105522899229309772982617502866007325956027585548405078270727633466267211050624656564238945850716779203730327916878271119577428176271969754456165419984065362456390318916774767522021729045399597591315611891108140065281321616087206253772073309910203724183588448605796453384336443087702604329292120130445296255439662298060469791689845218945601613926085313962850050990938926108899304092484976051143773698204117
    CIPHERTEXT = 3193986038350525893090702159154865322676713578163880901848638817656078665414602999880066556969734547766198986283534758377422240720577096502863266915422438080541129078568955350967592828705354081107456820933168871117016347100724846207292448602681003211364047489384742316691093640968000144178719843127858101509585453935672768246082612286649599839662198221389264400301570528463857780313399618691980893298857632780699090846552217101505149883643201135095510165949945628763829551365849168835567525912539527611526079333473792693641230455907968334191557774904274147083833161471644708546562126868780507179056526629161999331743205162099040689693775642680625521706450197256119735985666744834224640248686983404138290449671895590167249696037252598197915601229591535445487320671539063887379156595298716104972988527776308881623468101457945698990594263765611198385171929115724305863186002190189645217466538821008947101287837223337863236743255
    PUBLIC_EXPONENT = 65537

    cryptographer = RSACryptographer(MODULUS, CIPHERTEXT, PUBLIC_EXPONENT)
    analyzer = RSAAnalyzer(cryptographer)

    results = analyzer.analyze_and_decrypt()

    print("Результаты анализа RSA:")
    print(f"p = {results['prime_p']}")
    print(f"q = {results['prime_q']}")
    print(f"Проверка p*q == N: {results['verification']}")
    print(f"Длина модуля в битах: {results['modulus_bit_length']}")
    print(f"Расшифрованное сообщение: {results['decrypted_message']}")


if __name__ == "__main__":
    main()