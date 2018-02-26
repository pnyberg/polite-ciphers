//
//  main.h
//  AES-cipher-128
//
//  Created by Per Nyberg on 2018-02-24.
//  Copyright © 2018 Per Nyberg. All rights reserved.
//

#ifndef main_h
#define main_h

#include <vector>

using namespace std;

void fill_round_key_list(int* key_expansion_array[]);

bool fill_state_array(int* state_array[]);

void sub_and_rot_word(int column[]);

void apply_s_box(int& state_byte);

int gf_multiplication(int state_byte);

void do_aes();

void do_aes_rounds(int* state_array[], int* round_key_list[]);

void add_round_key(int* state_array[], int* round_key_list[], int round_index);

void sub_bytes(int* state_array[]);

void shift_rows(int* state_array[]);

void mix_columns(int* state_array[]);

void print_results_as_bytes(int* state_array[]);

void print_results_as_hex(int* state_array[]);

#endif /* main_h */
