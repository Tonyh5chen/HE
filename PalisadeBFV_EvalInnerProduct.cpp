/****************************************************/
/* PALISADE BGV velocity calculator                 */
/* Original written by: Alycia N. Carey             */
/* Re-write and test by: Chen He                    */
/* Parts of code borrowed from:                     */
/* demo-packing.cpp                                 */
/* final velocity = V_i + at   m/s                  */
/****************************************************/

#include "palisade.h"
#include "math/matrix.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>

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

	//Check to see if BFVrns is available
	#ifdef NO_QUADMATH
	cout << "This program cannot run due to BFVrns not being available for this architecture." 
	exit(0);
	#endif
	srand(time(NULL));

	/*****Set up the CryptoContext*****/
	clock_t cc_clock;
	cc_clock = clock();
	//Parameter Selection based on standard parameters from HE standardization workshop
 	int plaintextModulus = 1032193; //536903681 //1032193
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;


	//Create the cryptoContext with the desired parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);
	
	//Enable wanted functions
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	//std::cout << "securityLevel:" << securityLevel << std::endl;
	cc_clock = clock() - cc_clock;

	/*****Generate Keys*****/ 
	clock_t key_clock;
	key_clock = clock();

	//Create the container for the public key   
	LPKeyPair<DCRTPoly> keyPair;

	//Generate the keyPair
	keyPair = cryptoContext->KeyGen();

	//Generate the relinearization key
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	//Generate the Sun Key
	cryptoContext->EvalSumKeyGen(keyPair.secretKey);

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	//Create and encode the plaintext vectors and variables
    int N = 4096; //2760 8192 16384 32768
	vector<int64_t> initial_velocity; //vector<int64_t> initial_velocity={1,2,3,4,5,6,7,8,9,1}; 
	vector<int64_t> times; //vector<int64_t> times= {10,14,24,23,18,9,13,7,9,1}; 
	vector<int64_t> acc;  //vector<int64_t> acc={1,2,3,2,1,2,1,2,9,1}; 

	for(int i = 0; i < N; i++)
	{
		int64_t a = rand() % 10 + 1;
		acc.push_back(a);

		int64_t b = rand() % 10 + 1;
		initial_velocity.push_back(b);

		int64_t c = rand() % 10 + 1;
		times.push_back(c);
	}

	//std::cout<< acc.size() << std::endl;
	Plaintext plain_acc = cryptoContext->MakePackedPlaintext(acc);
	Plaintext plain_initial_vel = cryptoContext->MakePackedPlaintext(initial_velocity);
	Plaintext plain_times = cryptoContext->MakePackedPlaintext(times);
	//Plaintext plain_N_mean = cryptoContext->MakePackedPlaintext(N_mean); //linear regression

	//Encrypt the encodings
	auto enc_acc = cryptoContext->Encrypt(keyPair.publicKey, plain_acc);
	auto enc_initial_vel = cryptoContext->Encrypt(keyPair.publicKey, plain_initial_vel);
	auto enc_times = cryptoContext->Encrypt(keyPair.publicKey, plain_times);
	//auto enc_N_mean = cryptoContext->Encrypt(keyPair.publicKey, plain_N_mean); //linear regression

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
  	clock_t eval_clock;
	eval_clock = clock();

	auto enc_acc_mult_times = cryptoContext->EvalMult(enc_acc, enc_times);                  
	auto enc_final_vel = cryptoContext->EvalAdd(enc_initial_vel, enc_acc_mult_times);		

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_velocity;
	cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel, &plain_final_velocity);

	dec_clock = clock() - dec_clock;

	//Test advance operations
	clock_t eval_sum_clock;
	eval_sum_clock = clock();
	//Evalsum
	auto enc_final_vel_sum = cryptoContext->EvalSum(enc_final_vel, N);
	eval_sum_clock = clock() - eval_sum_clock;
	//decrypt
	clock_t dec_sum_clock;
	dec_sum_clock = clock();

	Plaintext plain_final_velocity_sum;
	cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel_sum, &plain_final_velocity_sum);

	dec_sum_clock = clock() - dec_sum_clock;

	//EvalInnerProduct
	clock_t eval_IP_clock;
	eval_IP_clock = clock();
	auto enc_final_vel_InnerProduct = cryptoContext->EvalInnerProduct(enc_final_vel,enc_final_vel, N);
	eval_IP_clock = clock() - eval_IP_clock;

	clock_t dec_IP_clock;
	dec_IP_clock = clock();
	Plaintext plain_final_velocity_InnerProduct;
	cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel_InnerProduct, &plain_final_velocity_InnerProduct);
	dec_IP_clock = clock() - dec_IP_clock;

	// auto enc_final_vel_lr= cryptoContext->EvalLinRegression(enc_final_vel,enc_final_vel);
	// Plaintext plain_final_velocity_lr;
	// cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel_lr, &plain_final_velocity_lr);

	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;

	cout << "Acceleration: " << endl;
	print(plain_acc, N);

	cout << "Initial Velocity: " << endl;
	print(plain_initial_vel, N);

	cout << "Time: " << endl;
	print(plain_times, N);

	cout << " Final Velocity : " << endl;
	print(plain_final_velocity, N);

	// cout << " Final Velocity Sum: " << endl;
	// print(plain_final_velocity_sum, N);

	cout << " Final Velocity Inner Product: " << endl;
	print(plain_final_velocity_InnerProduct, N);

	return 0;
}
