
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#define xtime(x)   ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

#define MIX_COL_ORIG 1
#define SK_LEN 1024

typedef struct{
    int key_ind[4];
    int delta_coeff[4];
    int nb_comb;
    uint8_t key_combination[256][4];
} keyCol_t;

uint8_t ciphered_text_faulted[16] = { 0xd5, 0x2c, 0x34, 0x94, 0xae, 0x4c, 0x1b, 0xd9, 0xa7, 0xa7, 0xce, 0x5c, 0x50, 0xac, 0x3e, 0xcc };
uint8_t original_ciphered_text[16] = { 0xb3, 0x44, 0x53, 0x4e, 0x67, 0x11, 0xd4, 0x84, 0xe2, 0x65, 0xca, 0x71, 0xb0, 0xc3, 0x9b, 0xe9 };
    
uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};


uint8_t rcon[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };

void init_keyCol(keyCol_t *key, int ind0, int ind1, int ind2, int ind3, int delta0, int delta1, int delta2, int delta3){
    key->key_ind[1] = ind1;
    key->key_ind[2] = ind2;
    key->key_ind[3] = ind3;
    key->key_ind[0] = ind0;

    key->delta_coeff[0] = delta0;
    key->delta_coeff[1] = delta1;
    key->delta_coeff[2] = delta2;
    key->delta_coeff[3] = delta3;

    key->nb_comb = 0;
}

int test_eq(uint8_t i, uint8_t k, uint8_t d) {
    return ((inv_sbox[original_ciphered_text[i] ^ k] ^ inv_sbox[ciphered_text_faulted[i] ^ k]) == d);
}

void enumerate_k(keyCol_t *key){
    int nb_comb = 0;
    for(int delta = 0; delta<256; delta++){
        int counter0 = 0, counter1 = 0, counter2 = 0, counter3 = 0;

        //list declaration
        uint8_t k0[4] = {0, 0, 0, 0};
        uint8_t k1[4] = {0, 0, 0, 0};
        uint8_t k2[4] = {0, 0, 0, 0};
        uint8_t k3[4] = {0, 0, 0, 0};

        //delta declaration
        uint8_t two_delta;
        if(delta<128)
            two_delta = delta<<1;
        else
            two_delta = (delta<<1) ^ 0x1B;
            
        uint8_t three_delta = two_delta ^ delta;

        int delta_list[3];
        delta_list[0] = delta;
        delta_list[1] = two_delta;
        delta_list[2] = three_delta;

        for(int k = 0; k < 256; k++){
            if(test_eq(key->key_ind[0], k, delta_list[key->delta_coeff[0]-1])){
                k0[counter0] = (uint8_t) k;
                counter0++;
            }
        }
        if(counter0 == 0) continue;

        for(int k = 0; k < 256; k++){
            if(test_eq(key->key_ind[1], k, delta_list[key->delta_coeff[1]-1])){
                k1[counter1] = (uint8_t) k;
                counter1++;
            }
        }
        if(counter1 == 0) continue;

        for(int k = 0; k < 256; k++){
            if(test_eq(key->key_ind[2], k, delta_list[key->delta_coeff[2]-1])){
                k2[counter2] = (uint8_t) k;
                counter2++;
            }
        }
        if(counter2 == 0) continue;
        
        for(int k = 0; k < 256; k++){
            if(test_eq(key->key_ind[3], k, delta_list[key->delta_coeff[3]-1])){
                k3[counter3] = (uint8_t) k;
                counter3++;
            }
        }
        if(counter3 == 0) continue;
        
        for(int i = 0; i<counter0; i++){
            for(int j = 0; j<counter1; j++){
                for(int k=0; k<counter2; k++){
                    for(int l=0; l<counter3; l++){
                        key->key_combination[nb_comb][0] = k0[i];
                        key->key_combination[nb_comb][1] = k1[j];
                        key->key_combination[nb_comb][2] = k2[k];
                        key->key_combination[nb_comb][3] = k3[l];
                        nb_comb++;
                    }
                }
            }
        }
    }
    key->nb_comb = nb_comb;
}
 
void display_vector(const uint8_t v[16]) {
    for (int32_t i = 0; i < 16; i++) {
        printf("%.2x", v[i]);
    }
    printf("\n");
}


void display_bytes(bool k[256]) {
    for (int32_t i = 0; i < 256; i += 1) {
        if (k[i]) {
            printf("0x%.2x, ", i);
        }
    }
    printf("\n");
}


void sub_bytes(uint8_t x[4][4]) {
    for (int32_t i = 0; i < 4; i++) {
        for (int32_t j = 0; j < 4; j++) {
            x[i][j] = sbox[x[i][j]];
        }
    }
}


void shift_rows(uint8_t x[4][4]) {
    uint8_t tmp = x[1][0];
    x[1][0] = x[1][1];
    x[1][1] = x[1][2];
    x[1][2] = x[1][3];
    x[1][3] = tmp;

    tmp = x[2][0];
    x[2][0] = x[2][2];
    x[2][2] = tmp;;
    tmp = x[2][1];
    x[2][1] = x[2][3];
    x[2][3] = tmp;

    tmp = x[3][0];
    x[3][0] = x[3][3];
    x[3][3] = x[3][2];
    x[3][2] = x[3][1];
    x[3][1] = tmp;
}


void mix_columns(uint8_t state[4][4]) {
    uint8_t tmp, tm, t;
    for (int32_t i = 0; i < 4; i++) {
        t            = state[0][i];
        tmp          = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        tm           = state[0][i] ^ state[1][i];
        tm           = xtime(tm);
        state[0][i] ^= tm ^ tmp;
        tm           = state[1][i] ^ state[2][i];
        tm           = xtime(tm);
        state[1][i] ^= tm ^ tmp;
        tm           = state[2][i] ^ state[3][i];
        tm           = xtime(tm);
        state[2][i] ^= tm ^ tmp;
        tm           = state[3][i] ^ t;
        tm           = xtime(tm);
        state[3][i] ^= tm ^ tmp;
    }
}


void add_round_key(uint8_t x[4][4], int32_t round, uint8_t round_key[176]) {
    for (int32_t i = 0; i < 4; i++) {
        for (int32_t j = 0; j < 4; j++) {
            x[j][i] ^= round_key[round * 16 + i * 4 + j];
        }
    }
}


void key_schedule(const uint8_t key[16], uint8_t round_key[176]) {
    for (int32_t i = 0; i < 16; i += 1) {
        round_key[i] = key[i];
    }
    for (int32_t r = 1; r < 11; r += 1) {
        round_key[r * 16 + 0] = round_key[(r - 1) * 16 + 0] ^ sbox[round_key[(r - 1) * 16 + 13]] ^ rcon[r - 1];
        round_key[r * 16 + 1] = round_key[(r - 1) * 16 + 1] ^ sbox[round_key[(r - 1) * 16 + 14]];
        round_key[r * 16 + 2] = round_key[(r - 1) * 16 + 2] ^ sbox[round_key[(r - 1) * 16 + 15]];
        round_key[r * 16 + 3] = round_key[(r - 1) * 16 + 3] ^ sbox[round_key[(r - 1) * 16 + 12]];

        for (int32_t b = 4; b < 16; b += 1) {
            round_key[r * 16 + b] = round_key[(r - 1) * 16 + b] ^ round_key[r * 16 + b - 4];
        }
    }
}


void inv_key_schedule(uint8_t key[16], uint8_t round_key[16], int round) {
    uint8_t key_temp[16] = {0};
    for (int32_t i = 0; i < 16; i += 1) {
        key[i] = round_key[i];
        key_temp[i] = round_key[i];
    }
    for (int32_t r = round-1; r >= 0; r--) {
        for (int32_t b = 4; b < 16; b += 1) {
            key[b] = key_temp[b] ^ key_temp[b - 4];
        }

        key[0] = key_temp[0] ^ sbox[key[13]] ^ rcon[r];
        key[1] = key_temp[1] ^ sbox[key[14]];
        key[2] = key_temp[2] ^ sbox[key[15]];
        key[3] = key_temp[3] ^ sbox[key[12]];

        for (int32_t i = 0; i < 16; i++) {
            key_temp[i] = key[i];
        }
    }
}


void aes_no_key_schedule(const uint8_t plain_text[16], uint8_t round_key[176], uint8_t ciphered_text[16]) {   
    uint8_t x[4][4];

    for (int32_t i = 0; i < 4; i++) {
        for (int32_t j = 0; j < 4; j++) {
            x[i][j] = plain_text[i * 4 + j];
        }
    }

    // 2. Rounds
    for (int32_t round = 0; round < 9; round++) {
        // a. add round key
        add_round_key(x, round, round_key);

        // b. SBox
        sub_bytes(x);

        // c. Shift rows
        shift_rows(x);

        // d. Mix columns
        mix_columns(x);
    }

    // 3. Final Round (no Mix Columns)
    add_round_key(x, 9, round_key);
    sub_bytes(x);
    shift_rows(x);
    add_round_key(x, 10, round_key);

    // Writing output ciphered text
    for (int32_t i = 0; i < 16; i++) {
        ciphered_text[i] = x[i % 4][i / 4];
    }
}


void aes(const uint8_t plain_text[16], const uint8_t key[16], uint8_t ciphered_text[16]) {
    uint8_t round_key[176];

    key_schedule(key, round_key);
    aes_no_key_schedule(plain_text, round_key, ciphered_text);
}


void dfa(uint8_t key[16], uint8_t plain_text[16], uint8_t ciphered_text[16]) {

    //initalisation
    int found = 0;
    keyCol_t k0_13_10_7;
    keyCol_t k4_1_14_11;
    keyCol_t k8_5_2_15;
    keyCol_t k12_9_6_3;

    //param : the key structure(1), the key indices(2-5), the delta coefficient(7-10) 
    init_keyCol(&k0_13_10_7, 0, 13, 10, 7, 2, 1, 1, 3);
    init_keyCol(&k4_1_14_11, 4, 1, 14, 11, 1, 1, 3, 2);
    init_keyCol(&k8_5_2_15, 8, 5, 2, 15, 1, 3, 2, 1);
    init_keyCol(&k12_9_6_3, 12, 9, 6, 3, 3, 2, 1, 1);

    enumerate_k(&k0_13_10_7);
    enumerate_k(&k4_1_14_11);
    enumerate_k(&k8_5_2_15);
    enumerate_k(&k12_9_6_3);

    uint8_t round_key[16] = {0};
    //search for the key
    for(int i = 0; i< k0_13_10_7.nb_comb && !found; i++){
        for(int j = 0; j< k4_1_14_11.nb_comb && !found; j++){
            for(int k = 0; k<k8_5_2_15.nb_comb && !found; k++){
                for(int l=0; l<k12_9_6_3.nb_comb && !found; l++){
                    round_key[k0_13_10_7.key_ind[0]] = k0_13_10_7.key_combination[i][0];
                    round_key[k0_13_10_7.key_ind[1]] = k0_13_10_7.key_combination[i][1];
                    round_key[k0_13_10_7.key_ind[2]] = k0_13_10_7.key_combination[i][2];
                    round_key[k0_13_10_7.key_ind[3]] = k0_13_10_7.key_combination[i][3];

                    round_key[k4_1_14_11.key_ind[0]] = k4_1_14_11.key_combination[j][0];
                    round_key[k4_1_14_11.key_ind[1]] = k4_1_14_11.key_combination[j][1];
                    round_key[k4_1_14_11.key_ind[2]] = k4_1_14_11.key_combination[j][2];
                    round_key[k4_1_14_11.key_ind[3]] = k4_1_14_11.key_combination[j][3];

                    round_key[k8_5_2_15.key_ind[0]] = k8_5_2_15.key_combination[k][0];
                    round_key[k8_5_2_15.key_ind[1]] = k8_5_2_15.key_combination[k][1];
                    round_key[k8_5_2_15.key_ind[2]] = k8_5_2_15.key_combination[k][2];
                    round_key[k8_5_2_15.key_ind[3]] = k8_5_2_15.key_combination[k][3];

                    round_key[k12_9_6_3.key_ind[0]] = k12_9_6_3.key_combination[l][0];
                    round_key[k12_9_6_3.key_ind[1]] = k12_9_6_3.key_combination[l][1];
                    round_key[k12_9_6_3.key_ind[2]] = k12_9_6_3.key_combination[l][2];
                    round_key[k12_9_6_3.key_ind[3]] = k12_9_6_3.key_combination[l][3];

                    //since we only have the 10th round key, we need to do an inverse_key_schedule
                    inv_key_schedule(key, round_key, 10);
                    aes(plain_text, key, ciphered_text);
                    found = 1;
                    for(int z = 0; z<16 && found; z++){
                        if(ciphered_text[z] != original_ciphered_text[z]){
                            found = 0;
                        }
                    }                    
                }
            }
        }
    }


    if(found){
        printf("Found key:                         ");
        display_vector(key);
    }
    else{
        printf("NO KEY FOUND!\n");
    }
    
}


int main() {
    uint8_t plain_text[16] = { 0x6c, 0xdf, 0x1e, 0x56, 0x51, 0xa1, 0x79, 0x6b, 0x9b, 0x6b, 0x9a, 0xce, 0x43, 0x1d, 0xb5, 0x98 };
    uint8_t key[16]        = { 0x00 };

    uint8_t ciphered_text[16] = { 0x00 };
    

    srand(5);

    printf("Plain text:                        ");
    display_vector(plain_text);

    printf("Ciphered text (AES) without fault: ");
    display_vector(original_ciphered_text);

    printf("Ciphered text (AES) with fault:    ");
    display_vector(ciphered_text_faulted);

    dfa(key, plain_text, ciphered_text);
    
    return 0;
}



