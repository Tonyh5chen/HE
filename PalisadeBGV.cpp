/****************************************************/
/* PALISADE BGV velocity calculator    				*/
/* Original written by: Alycia N. Carey             */
/* Update and test by: Chen He 						*/
/* Parts of code borrowed from:        				*/
/* demo-packing.cpp                    				*/
/* final velocity = V_i + at   m/s     				*/
/****************************************************/

#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <random>
#include <iterator>


using namespace std;
using namespace lbcrypto;

void print(Plaintext v, int length)
	{

	    int print_size = 20;
	    int end_size = 2;

	    cout << endl;
	    cout << "    [";

	    for (int i = 0; i < print_size; i++)
		    {
		        cout << setw(3) << right << v->GetPackedValue()[i] << ",";
		    }

	    cout << setw(3) << " ...,";

	    for (int i = length - end_size; i < length; i++)
		    {
		        cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
		    }
	    
	    cout << endl;
	};

int main()
{
	/*****Parameter Generation*****/
	clock_t cc_clock;
	cc_clock = clock();
	//test
  	// Set the main parameters
 	int plaintextModulus = 1032193;
 	double sigma = 3.2;
 	SecurityLevel securityLevel = HEStd_128_classic;
 	uint32_t depth = 2;

	// Instantiate the crypto context
	 CryptoContext<DCRTPoly> cc = 
	 CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

	// Enable features that you wish to use
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);



	cc_clock = clock() - cc_clock;

	//std::cout << "Number of Slots:" << batchSize << std::endl;
	/*****KeyGen*****/
	clock_t key_clock;
	key_clock = clock();

	// LPKeyPair<Poly> kp = cc->KeyGen();
	// cc->EvalSumKeyGen(kp.secretKey);
	// cc->EvalMultKeyGen(kp.secretKey);
	  // Initialize Public Key Containers
  	LPKeyPair<DCRTPoly> keyPair;

 	 // Generate a public/private key pair
  	keyPair = cc->KeyGen();

 	 // Generate the relinearization key
 	cc->EvalMultKeyGen(keyPair.secretKey);


	key_clock = clock() - key_clock;

	/*****Encode and Encrypt*****/

	//Generate the vectors for Vi time and acc
	vector<int64_t> initial_velocity; //vector<int64_t> initial_velocity={1,2,3,4,5,6,7,8,9,1}; 
	vector<int64_t> times; //vector<int64_t> times= {10,14,24,23,18,9,13,7,9,1}; 
	vector<int64_t> acc;  //vector<int64_t> acc={1,2,3,2,1,2,1,2,9,1}; 

	int N = 2760; //4096 8192
	for(int i = 0; i < N; i++)
	{
		int64_t a = rand() % 100 + 1; //final velocity value will be overflow if approximaly more than 100
		acc.push_back(a);

		int64_t b = rand() % 100 + 1;
		initial_velocity.push_back(b);

		int64_t c = rand() % 100 + 1;
		times.push_back(c);
	}

    //start the clock
	clock_t enc_clock;
	enc_clock = clock();

	Plaintext plain_acc = cc->MakePackedPlaintext(acc);
	Plaintext plain_initial_vel = cc->MakePackedPlaintext(initial_velocity);
	Plaintext plain_times = cc->MakePackedPlaintext(times);

	auto enc_initial_vel = cc->Encrypt(keyPair.publicKey, plain_initial_vel);
	auto enc_times = cc->Encrypt(keyPair.publicKey, plain_times);
	auto enc_acc = cc->Encrypt(keyPair.publicKey, plain_acc);

	enc_clock = clock() - enc_clock;

	// std::cout << "Initial Velocity \n\t" << initial_velocity << std::endl;
	// std::cout << "Times \n\t" << times << std::endl;
	// std::cout << "Acceleration \n\t" << acc << std::endl;

	/*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

	auto enc_final_vel = cc->EvalMult(enc_times, enc_acc);
	enc_final_vel = cc->EvalAdd(enc_final_vel, enc_initial_vel);
	
	eval_clock = clock() - eval_clock;
	
	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_vel;

	cc->Decrypt(keyPair.secretKey, enc_final_vel, &plain_final_vel);
	
	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;

	cout << "Acceleration: " << endl;
	print(plain_acc, N);

	cout << "Initial Velocity: " << endl;
	print(plain_initial_vel, N);

	cout << "Time: " << endl;
	print(plain_times, N);

	cout << " Final Velocity: " << endl;
	print(plain_final_vel, N);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

}
