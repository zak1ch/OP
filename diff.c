#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>

void Generate_Big_Number(mpz_t random_number, unsigned long int min_bit_len, unsigned long int max_bit_len) {
    gmp_randstate_t random_state;
    gmp_randinit_default(random_state);

    unsigned long int random_seed = time(NULL);
    gmp_randseed_ui(random_state, random_seed);

    unsigned long int bit_len = min_bit_len + rand() % (max_bit_len - min_bit_len + 1);

    mpz_urandomb(random_number, random_state, bit_len);

    while (!mpz_probab_prime_p(random_number, 120)) {
        bit_len = min_bit_len + rand() % (max_bit_len - min_bit_len + 1);
        mpz_urandomb(random_number, random_state, bit_len);
    }

    gmp_randclear(random_state);
}

void Diffi_Hellman(const mpz_t p, const mpz_t g) {
    mpz_t A_private, B_private;
    mpz_t A_public, B_public;
    mpz_t A_com_secret, B_com_secret;
    mpz_inits(A_private, B_private, A_public, B_public, A_com_secret, B_com_secret, NULL);

    Generate_Big_Number(A_private, 40, 2048);
    Generate_Big_Number(B_private, 40, 2048);

    mpz_powm(A_public, g, A_private, p);
    mpz_powm(B_public, g, B_private, p);

    mpz_powm(A_com_secret, B_public, A_private, p);
    mpz_powm(B_com_secret, A_public, B_private, p);

    gmp_printf("Закрытый ключ A: %Zd\n\n", A_private);
    gmp_printf("Закрытый ключ B: %Zd\n\n", B_private);
    gmp_printf("Открытый ключ A: %Zd\n\n", A_public);
    gmp_printf("Открытый ключ B: %Zd\n\n", B_public);
    gmp_printf("Общий секретный ключ со стороны A: %Zd\n\n", A_com_secret);
    gmp_printf("Общий секретный ключ со стороны B: %Zd\n\n", B_com_secret);

    mpz_clears(A_private, B_private, A_public, B_public, A_com_secret, B_com_secret, NULL);
}

int main(void) {
    mpz_t p, g;
    mpz_inits(p, g, NULL);

    Generate_Big_Number(p, 40, 4096);
    Generate_Big_Number(g, 40, 4096);

    gmp_printf("p: %Zd\n\n", p);
    gmp_printf("g: %Zd\n\n", g);

    Diffi_Hellman(p, g);

    mpz_clears(p, g, NULL);

    return 0;
}
