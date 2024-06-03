#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int Generate_RSA_Keys(const char *PUBLIC_KEY_FILE, const char *PRIVATE_KEY_FILE) {
    int bits = 2048;
    unsigned long e = RSA_F4;

    RSA *rsa = RSA_new();
    BIGNUM *exponent = BN_new();
    BN_set_word(exponent, e);

    if (RSA_generate_key_ex(rsa, bits, exponent, NULL) != 1) {
        printf("Ошибка генерации ключей RSA\n");
        RSA_free(rsa);
        BN_free(exponent);
        return 1;
    }

    FILE *public_key_file_write = fopen(PUBLIC_KEY_FILE, "wb");
    if (!public_key_file_write) {
        printf("Ошибка открытия файла для открытого ключа\n");
        RSA_free(rsa);
        BN_free(exponent);
        return 1;
    }

    if (PEM_write_RSA_PUBKEY(public_key_file_write, rsa) != 1) {
        printf("Ошибка записи открытого ключа в файл\n");
        RSA_free(rsa);
        BN_free(exponent);
        fclose(public_key_file_write);
        return 1;
    }
    fclose(public_key_file_write);

    FILE *private_key_file_write = fopen(PRIVATE_KEY_FILE, "wb");
    if (!private_key_file_write) {
        printf("Ошибка открытия файла для закрытого ключа\n");
        RSA_free(rsa);
        BN_free(exponent);
        return 1;
    }

    if (PEM_write_RSAPrivateKey(private_key_file_write, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        printf("Ошибка записи закрытого ключа в файл\n");
        RSA_free(rsa);
        BN_free(exponent);
        fclose(private_key_file_write);
        return 1;
    }
    fclose(private_key_file_write);

    RSA_free(rsa);
    BN_free(exponent);
    return 0;
}


int Encrypt(const char *PUBLIC_KEY_FILE, const char *INPUT_FILE, const char *OUTPUT_FILE) {
    FILE *public_key_file_write = fopen(PUBLIC_KEY_FILE, "rb");
    if (!public_key_file_write) {
        printf("Ошибка открытия открытого ключа\n");
        return -1;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(public_key_file_write, NULL, NULL, NULL);
    fclose(public_key_file_write);

    if (!rsa) {
        printf("Ошибка чтения открытого ключа\n");
        ERR_print_errors_fp(stdout); 
    }

    FILE *input_file_read = fopen(INPUT_FILE, "rb");
    if (!input_file_read) {
        printf("Ошибка открытия входного файла\n");
        RSA_free(rsa);
        return -1;
    }

    fseek(input_file_read, 0, SEEK_END);
    unsigned long input_len = ftell(input_file_read);
    fseek(input_file_read, 0, SEEK_SET);

    unsigned char *data_file = (unsigned char *)malloc(input_len);
    if (!data_file) {
        printf("Ошибка выделения памяти для входных данных\n");
        fclose(input_file_read);
        RSA_free(rsa);
        return -1;
    }

    fread(data_file, input_len, 1, input_file_read);
    fclose(input_file_read);

    int rsa_key_len = RSA_size(rsa);
    unsigned char *encrypted = (unsigned char *)malloc(rsa_key_len);
    if (!encrypted) {
        printf("Ошибка выделения памяти для зашифрованных данных\n");
        free(data_file);
        RSA_free(rsa);
        return -1;
    }

    int encrypt_file = RSA_public_encrypt(input_len, data_file, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (encrypt_file == -1) {
        printf("Ошибка шифрования данных\n");
        ERR_print_errors_fp(stdout); 
        free(data_file);
        free(encrypted);
        RSA_free(rsa);
        return -1;
    }

    FILE *output_file_write = fopen(OUTPUT_FILE, "wb");
    if (!output_file_write) {
        printf("Ошибка открытия выходного файла\n");
        free(data_file);
        free(encrypted);
        RSA_free(rsa);
        return -1;
    }

    fwrite(encrypted, encrypt_file, 1, output_file_write);
    fclose(output_file_write);
    free(data_file);
    free(encrypted);
    RSA_free(rsa);

    return 0;
}

int Decrypt(const char *PRIVATE_KEY_FILE, const char *INPUT_FILE, const char *OUTPUT_FILE) {
    FILE *private_key_file_read = fopen(PRIVATE_KEY_FILE, "rb");
    if (!private_key_file_read) {
        printf("Ошибка открытия закрытого ключа\n");
        return -1;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(private_key_file_read, NULL, NULL, NULL);
    fclose(private_key_file_read);

    if (!rsa) {
        printf("Ошибка чтения закрытого ключа\n");
        ERR_print_errors_fp(stdout); 
        return -1;
    }

    FILE *input_file_read = fopen(INPUT_FILE, "rb");
    if (!input_file_read) {
        printf("Ошибка открытия входного файла\n");
        RSA_free(rsa);
        return -1;
    }

    fseek(input_file_read, 0, SEEK_END);
    unsigned long input_len = ftell(input_file_read);
    fseek(input_file_read, 0, SEEK_SET);

    unsigned char *decryption_data_file = (unsigned char *)malloc(input_len);
    if (!decryption_data_file) {
        printf("Ошибка выделения памяти для зашифрованных данных\n");
        fclose(input_file_read);
        RSA_free(rsa);
        return -1;
    }

    fread(decryption_data_file, input_len, 1, input_file_read);
    fclose(input_file_read);

    unsigned char *decrypted = (unsigned char *)malloc(RSA_size(rsa));
    if (!decrypted) {
        printf("Ошибка выделения памяти для расшифрованных данных\n");
        RSA_free(rsa);
        free(decryption_data_file);
        return -1;
    }

    int encrypt_file = RSA_private_decrypt(input_len, decryption_data_file, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (encrypt_file == -1) {
        printf("Ошибка расшифрования данных\n");
        ERR_print_errors_fp(stdout);
        RSA_free(rsa);
        free(decryption_data_file);
        free(decrypted);
        return -1;
    }

    FILE *output_file_write = fopen(OUTPUT_FILE, "wb");
    if (!output_file_write) {
        printf("Ошибка открытия выходного файла\n");
        RSA_free(rsa);
        free(decryption_data_file);
        free(decrypted);
        return -1;
    }

    fwrite(decrypted, encrypt_file, 1, output_file_write);
    fclose(output_file_write);
    RSA_free(rsa);
    free(decryption_data_file);
    free(decrypted);
    return 0;
}

int main(void) {
    int num;
    do {
        printf("Выберите действие:\n");
        printf("1. Сгенерировать ключи RSA.\n");
        printf("2. Зашифровать файл.\n");
        printf("3. Расшифровать файл.\n");
        printf("0. Выйти.\n");
        printf("Введите номер выбранного действия: ");
        scanf("%d", &num);

        if (num == 1) {
            char PUBLIC_KEY_FILE[256];
            char PRIVATE_KEY_FILE[256];

            printf("Введите имя файла для сохранения открытого ключа: ");
            scanf("%s", PUBLIC_KEY_FILE);
            printf("Введите имя файла для сохранения закрытого ключа: ");
            scanf("%s", PRIVATE_KEY_FILE);

            Generate_RSA_Keys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
            printf("Ключи RSA сгенерированы и сохранены в файлы %s и %s\n\n", PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
        } else if (num == 2) {
            char PUBLIC_KEY_FILE[256];
            char INPUT_FILE[256];
            char OUTPUT_FILE[256];

            printf("Введите имя файла с открытым ключом: ");
            scanf("%s", PUBLIC_KEY_FILE);
            printf("Введите имя файла для шифрования: ");
            scanf("%s", INPUT_FILE);
            printf("Введите имя файла для сохранения зашифрованного сообщения: ");
            scanf("%s", OUTPUT_FILE);

            if (Encrypt(PUBLIC_KEY_FILE, INPUT_FILE, OUTPUT_FILE) == 0) {
                printf("Файл зашифрован и сохранен в %s\n\n", OUTPUT_FILE);
            } else {
                printf("Ошибка шифрования\n");
            }
        } else if (num == 3) {
            char PRIVATE_KEY_FILE[256];
            char INPUT_FILE[256];
            char OUTPUT_FILE[256];

            printf("Введите имя файла с закрытым ключом: ");
            scanf("%s", PRIVATE_KEY_FILE);
            printf("Введите имя файла с зашифрованным сообщением: ");
            scanf("%s", INPUT_FILE);
            printf("Введите имя файла для сохранения расшифрованного сообщения: ");
            scanf("%s", OUTPUT_FILE);

            if (Decrypt(PRIVATE_KEY_FILE, INPUT_FILE, OUTPUT_FILE) == 0) {
                printf("Файл расшифрован и сохранен в %s\n\n", OUTPUT_FILE);
            } else {
                printf("Ошибка расшифрования\n");
            }
        } else if (num == 0) {
            printf("Выход из программы.\n");
        } else {
            printf("Неверный выбор\n");
        }
    } while (num != 0);

    return 0;
}