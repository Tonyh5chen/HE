/****************************************************/
/* PALISADE BGV velocity calculator                 */
/* Original written by: Alycia N. Carey             */
/* Re-write and test by: Chen He                    */
/* Parts of code borrowed from:                     */
/* demo-packing.cpp                                 */
/* final velocity = V_i + at   m/s                  */
/****************************************************/

#include <iostream>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include "seal/seal.h"
#include "examples.h"

using namespace std;
using namespace seal;

int example_bfv_basics()
{
    /*****Choose Parameters*****/
    clock_t cc_clock;
    cc_clock = clock();

    EncryptionParameters parms(scheme_type::BFV);
    size_t poly_modulus_degree = 2048; //8192 or 16384 or 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto count=CoeffModulus::MaxBitCount(poly_modulus_degree);
    cout << "count: " << count << endl;
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    //Enable batching
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << "Parameter validation (success): " << context->parameter_error_message() << endl;
    //Verify that batching is enabled
    auto qualifiers = context->first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;
    cout << "Parameters for SEAL: " << boolalpha << qualifiers.parameters_set() << endl;

    /*****Generate keys and functions*****/
    clock_t key_clock;
    key_clock = clock();

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    //Serializable<RelinKeys> rlk = keygen.relin_keys();

    key_clock = clock() - key_clock;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    //Set up batch encoderbatch encoder
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    cout << "slot_count: "<< slot_count << endl;
    size_t row_size = slot_count / 2;
    
    
    cc_clock = clock() - cc_clock - key_clock;
    
    clock_t enc_clock;
    enc_clock = clock();
    //Generate the matrices of values 
    int N = slot_count; //or 100 or 1000 or 2760 or 4096 or 8192 or 16384 or 32768

    vector<uint64_t> initial_velocity;    
    vector<uint64_t> times;               
    vector<uint64_t> acc;               

    for(int i = 0; i < N; i++)
    {
        int64_t a = rand() % 100 + 1;
        acc.push_back(a);

        int64_t b = rand() % 100 + 1;
        initial_velocity.push_back(b);

        int64_t c = rand() % 1000 + 1;
        times.push_back(c);
    }
     
    /*****Encode*****/
    Plaintext plain_initial_vel;
    Plaintext plain_times;
    Plaintext plain_acc;

    batch_encoder.encode(initial_velocity, plain_initial_vel);
    batch_encoder.encode(times, plain_times);
    batch_encoder.encode(acc, plain_acc);

    /*****Encrypt*****/
    Ciphertext enc_initial_vel;
    Ciphertext enc_times;
    Ciphertext enc_acc;

    encryptor.encrypt(plain_initial_vel, enc_initial_vel);
    encryptor.encrypt(plain_times, enc_times);
    encryptor.encrypt(plain_acc, enc_acc);

    enc_clock = clock() - enc_clock;

    /*****Evaluate*****/
    clock_t eval_clock;
    eval_clock = clock();

    Ciphertext enc_final_vel;

    evaluator.multiply(enc_acc, enc_times, enc_final_vel);
    evaluator.add_inplace(enc_final_vel, enc_initial_vel);

    eval_clock = clock() - eval_clock;

    /*****Decrypt*****/
    clock_t dec_clock;
    dec_clock = clock();

    Plaintext plain_final_vel;
    vector<uint64_t> final_vel;

    decryptor.decrypt(enc_final_vel, plain_final_vel);
    //decryptor.decrypt(final_vel, plain_final_vel);
    dec_clock = clock() - dec_clock;

    /*****Decode*****/
    batch_encoder.decode(plain_final_vel, final_vel);
    
    /*****Print*****/
    cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;
    cout << "Acceleration: " << endl;
    // print_matrix(acc, row_size);
    print_vector(acc);
    cout << "Initial Velocity(size): " << initial_velocity.size() << endl;
    //print_matrix(initial_velocity, row_size);
    print_vector(initial_velocity);
    cout << "Time(size): " << times.size()<< endl;
    print_vector(times);
    //print_matrix(times, row_size);
    cout << " Final Velocity(size): "<<final_vel.size() << endl;
    //print_matrix(final_vel, row_size);
    print_vector(final_vel);

    cout << "Times:" <<endl;
    cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
    cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
    cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
    cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
    cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

    return 0;
}
