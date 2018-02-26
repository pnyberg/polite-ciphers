/**
 * This implementation sucks because it cannot pass Kattis for some fucking reason!
 * Therefore, this implementation is the worst of the bad.
 *
 * If you, yes I mean YOU, were to try to fix this. Write a fucking program that 
 *  creates a random key and a random message, runs it with both the java and the
 *  C++ implementations and compare their results. If this doesn't work, I don't 
 *  know what will.
 */

/**
 * An implementation of the AES-cipher
 * The implementation is based of the publication: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 *  as well as the Wikipedia-page: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey_step
 *  with double checking against the Youtube-clip: https://www.youtube.com/watch?v=mlzxpkdXP58&list=PL_TXpFNz1afEmeaaPwBa4SO2Ys1X7nKIA
 */

#include "main.h"

#include <iostream>
#include <vector>

using namespace std;

// Hardcode values (at least for out implementation)
const int word_length = 4; // length of the "words" used (32-bit)
const int Nb = 4; // number of columns for the state
const int Nk = 4; // number of columns for the key
const int Nr = 10; // number of rows

const int r_con[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

const int s_box_matrix[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

/**
 * Generate the round-keys (as a long list).
 * This is done through reading in from the input-stream given as a parameter.
 * The first 4x4 of the matrix is the given cipher-key, the rest is generated
 *  per AES-rules.
 */
void fill_round_key_list(int* key_expansion_array[]) {
    // save cipher key
    for (int i = 0 ; i < Nk ; i++) {
        for (int k = 0 ; k < word_length ; k++) {
            char c;
            cin >> std::noskipws >> c;
            int c_int = ((int)c + 256) % 256;
            key_expansion_array[i][k] = c_int;
        }
    }
    
    // generate the rest of the "columns"
    for (int index = Nk ; index < (Nb * (Nr+1)) ; index++) {
        // copy the content of index-1
        for (int i = 0 ; i < word_length ; i++) {
            key_expansion_array[index][i] = key_expansion_array[index-1][i];
        }
        // if it's the first word in that round key, do sub+rot as well as xor with r_con
        if (index % Nk == 0) {
            sub_and_rot_word(key_expansion_array[index]);
            key_expansion_array[index][0] = key_expansion_array[index][0] ^ r_con[index / Nk];
        }
        
        for (int k = 0 ; k < word_length ; k++) {
            key_expansion_array[index][k] = key_expansion_array[index - Nk][k] ^ key_expansion_array[index][k];
        }
    }
}

/**
 * Creates the state-array to be used in the cipher.
 * This is done through reading in from the input-stream given as a parameter.
 * The array is then returned as a 4x4-matrix.
 *
 * In case there is no more indata this method will return null,
 * 	signaling to the main-program that it should quit.
 */
bool fill_state_array(int* state_array[]) {
    for (int i = 0 ; i < Nk ; i++) {
        for (int k = 0 ; k < word_length ; k++) {
            if (cin.eof()) {
                return false;
            }
            char c;
            cin >> std::noskipws >> c;
            int c_int = ((int)c + 256) % 256;
            state_array[i][k] = c_int;
        }
    }
    
    // if c is -1 then there is no more data to be read
    /* if (c == -1) {
     return null;
     }
     */
    return true;
}

/**
 * This method does both the sub-word and the rot-word operations (first sub- then rot-word).
 */
void sub_and_rot_word(int column[]) {
    // sub word
    for (int i = 0 ; i < 4 ; i++) {
        apply_s_box(column[i]);
    }
    
    // rot word
    int temp = column[0];
    for (int i = 0 ; i < (4-1) ; i++) {
        column[i] = column[i+1];
    }
    column[3] = temp;
}

/**
 * This methods does the "S-box"-operation on the given "byte".
 * This is done through finding the row- and the column-values per AES-rules.
 * The S-box is hardcoded in to the program.
 */
void apply_s_box(int& state_byte) {
    int row = state_byte >> 4;
    int column = state_byte & 0xf;
    
    state_byte = s_box_matrix[row][column];
}

/**
 * This methods is the main AES-128-method call
 */
void do_aes() {
    // setting up the key-extenion-matrix (4-byte-words x number of words x (Number of rounds + 1)
    int** key_expansion_array = new int*[Nb * (Nr + 1)];
    for (int i = 0 ; i < Nb * (Nr + 1) ; i++) {
        key_expansion_array[i] = new int[word_length];
    }
    
    fill_round_key_list(key_expansion_array);
    
    // setting up the key-extenion-matrix (4-byte-words x number of words x (Number of rounds + 1)
    int** state_array = new int*[Nk];
    for (int i = 0 ; i < Nk ; i++) {
        state_array[i] = new int[word_length];
    }
    
    while(true) {
        bool next_round_exists = fill_state_array(state_array);
        
        if (!next_round_exists) {
            break;
        }
        
        do_aes_rounds(state_array, key_expansion_array);
        
        print_results_as_bytes(state_array);
        // debugging
        /*
        cout << endl;
        print_results_as_hex(state_array);
        */
        // end debugging
    }
}

/**
 * Does the AES-procedure (add round key, sub bytes, shift rows, mix columns)
 *  as per AES-rules.
 * First and last add_round_key-operation is hardcoded due to known values (0 and Nr)
 */
// int[][] state_array, int[][]round_key_list
void do_aes_rounds(int* state_array[], int* round_key_list[]) {
    add_round_key(state_array, round_key_list, 0);
    
    for (int round_index = 1 ; round_index < Nr ; round_index++) {
        sub_bytes(state_array);
        shift_rows(state_array);
        mix_columns(state_array);
        add_round_key(state_array, round_key_list, round_index);
    }
    
    sub_bytes(state_array);
    shift_rows(state_array);
    add_round_key(state_array, round_key_list, Nr);
}

/**
 * Performs the "add round key"-operation.
 * A xor-operation according to AES-specification.
 */
void add_round_key(int* state_array[], int* round_key_list[], int round_index) {
    for (int i = 0 ; i < Nk ; i++) {
        for (int k = 0 ; k < word_length ; k++) {
            state_array[i][k] = state_array[i][k] ^ round_key_list[round_index * Nk + i][k];
        }
    }
}

/**
 * Performs the "sub bytes"-operation.
 * Uses the S-box on all "bytes" in the state-array.
 */
void sub_bytes(int* state_array[]) {
    for (int i = 0 ; i < Nk ; i++) {
        for (int k = 0 ; k < word_length ; k++) {
            apply_s_box(state_array[i][k]);
        }
    }
}

/**
 * Performs the "shift rows"-operation.
 * Shifts rows according to AES-specification.
 *
 * In this case improvements have been made to prevent unnecessary
 *  movements on the third and fourth row (just one move instead of
 *  several).
 */
void shift_rows(int* state_array[]) {
    // first row - do nothing
    
    // second row - 1 shift
    int temp = state_array[0][1];
    for (int n = 0 ; n < 3 ; n++) {
        state_array[n][1] = state_array[n + 1][1];
    }
    state_array[3][1] = temp;
    
    // third row - 2 shifts
    temp = state_array[0][2];
    state_array[0][2] = state_array[2][2];
    state_array[2][2] = temp;
    
    temp = state_array[1][2];
    state_array[1][2] = state_array[3][2];
    state_array[3][2] = temp;
    
    // fourth row - 3 shifts (-1 shift)
    temp = state_array[3][3];
    for (int n = 2 ; n >= 0 ; n--) {
        state_array[n+1][3] = state_array[n][3];
    }
    state_array[0][3] = temp;
}

/**
 * Performs the "mix columns"-operation.
 * Mixes the columns with xor according to the AES-specification.
 *
 * All the possible calculated values (multiples with 1, 2 and 3) are
 *  done in advance because they will always be used (and prevents
 *  double work in some cases).
 */
void mix_columns(int* state_array[]) {
    for (int k = 0 ; k < 4 ; k++) {
        int first_one = state_array[k][0];
        int first_two = gf_multiplication(state_array[k][0]);
        int first_three = first_two ^ state_array[k][0];
        
        int second_one = state_array[k][1];
        int second_two = gf_multiplication(state_array[k][1]);
        int second_three = second_two ^ state_array[k][1];
        
        int third_one = state_array[k][2];
        int third_two = gf_multiplication(state_array[k][2]);
        int third_three = third_two ^ state_array[k][2];
        
        int fourth_one = state_array[k][3];
        int fourth_two = gf_multiplication(state_array[k][3]);
        int fourth_three = fourth_two ^ state_array[k][3];
        
        state_array[k][0] = first_two ^ second_three ^ third_one ^ fourth_one;
        state_array[k][1] = first_one ^ second_two ^ third_three ^ fourth_one;
        state_array[k][2] = first_one ^ second_one ^ third_two ^ fourth_three;
        state_array[k][3] = first_three ^ second_one ^ third_one ^ fourth_two;
    }
}

/**
 * Performs the "multiply by 2"-operation for the "mix columns"-operation.
 * It also does a "highest bit"-check to see if xor with 0x1b is necessary.
 */
int gf_multiplication(int state_byte) {
    if (state_byte >> 7 == 1) {
        return (state_byte << 1 & 0xff) ^ 0x1b;
    }
    
    return state_byte << 1 & 0xff;
}

/**
 * Prints the content of the state-array as a single "string".
 * Commented code is used for checking the result in hexadecimal, if
 *  that is wished for.
 */
void print_results_as_bytes(int* state_array[]) {
    for (int i = 0 ; i < 4 ; i++) {
        for (int k = 0 ; k < 4 ; k++) {
            int c = state_array[i][k];
            cout << (char)c; // <--- print in the fucking byte-format you bastard
        }
    }
}

void print_results_as_hex(int* state_array[]) {
    for (int i = 0 ; i < 4 ; i++) {
        for (int k = 0 ; k < 4 ; k++) {
            int c = state_array[i][k];
            if (c <= 15) {
                cout << "0";
            }
            cout << hex << c;
        }
    }
        cout << endl;
}

/**
 * The main-program.
 * - Creates an input-stream (System.in).
 * - Generates the "round key"-list
 * - Loops as long as input can be found in "create_state_array"-subroutine
 * - Creates state-arrays which are used in the "do_aes"-subroutine
 * - Does the "AES-ciphering" (for every state-array)
 * - Prints the resulting ciphertext (for every state-array)
 */
int main(int argc, const char * argv[]) {
    do_aes();
/*
    int** key_expansion_array = new int*[Nb * (Nr + 1)];
    for (int i = 0 ; i < Nb * (Nr + 1) ; i++) {
        key_expansion_array[i] = new int[word_length];
    }

    // save the key
    key_expansion_array[0][0] = 0x2b;
    key_expansion_array[0][1] = 0x7e;
    key_expansion_array[0][2] = 0x15;
    key_expansion_array[0][3] = 0x16;

    key_expansion_array[1][0] = 0x28;
    key_expansion_array[1][1] = 0xae;
    key_expansion_array[1][2] = 0xd2;
    key_expansion_array[1][3] = 0xa6;

    key_expansion_array[2][0] = 0xab;
    key_expansion_array[2][1] = 0xf7;
    key_expansion_array[2][2] = 0x15;
    key_expansion_array[2][3] = 0x88;

    key_expansion_array[3][0] = 0x09;
    key_expansion_array[3][1] = 0xcf;
    key_expansion_array[3][2] = 0x4f;
    key_expansion_array[3][3] = 0x3c;

    // generate the rest of the "columns"
    for (int index = Nk ; index < (Nb * (Nr+1)) ; index++) {
        // copy the content of index-1
        for (int i = 0 ; i < word_length ; i++) {
            key_expansion_array[index][i] = key_expansion_array[index-1][i];
        }
        // if it's the first word in that round key, do sub+rot as well as xor with r_con
        if (index % Nk == 0) {
            sub_and_rot_word(key_expansion_array[index]);
            key_expansion_array[index][0] = key_expansion_array[index][0] ^ r_con[index / Nk];
        }
        
        for (int k = 0 ; k < word_length ; k++) {
            key_expansion_array[index][k] = key_expansion_array[index - Nk][k] ^ key_expansion_array[index][k];
        }
    }
    
    // setting up the key-extenion-matrix (4-byte-words x number of words x (Number of rounds + 1)
    int** state_array = new int*[Nk];
    for (int i = 0 ; i < Nk ; i++) {
        state_array[i] = new int[word_length];
    }
    
    while(true) {
        //bool next_round_exists = fill_state_array(state_array);
        int** state_array = new int*[Nk];
        for (int i = 0 ; i < Nk ; i++) {
            state_array[i] = new int[word_length];
        }
        
        state_array[0][0] = 0x32;
        state_array[0][1] = 0x43;
        state_array[0][2] = 0xf6;
        state_array[0][3] = 0xa8;
        
        state_array[1][0] = 0x88;
        state_array[1][1] = 0x5a;
        state_array[1][2] = 0x30;
        state_array[1][3] = 0x8d;
        
        state_array[2][0] = 0x31;
        state_array[2][1] = 0x31;
        state_array[2][2] = 0x98;
        state_array[2][3] = 0xa2;
        
        state_array[3][0] = 0xe0;
        state_array[3][1] = 0x37;
        state_array[3][2] = 0x07;
        state_array[3][3] = 0x34;
        
        do_aes_rounds(state_array, key_expansion_array);
 
        cout << "-------" << endl;
        print_results_as_hex(state_array);
        print_results_as_oct(state_array);
        
        break;
    }*/
    
    return 0;
}
