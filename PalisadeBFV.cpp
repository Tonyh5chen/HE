/***************************************/
/* PALISADE BFVrns velocity calculator */
/* Author: Alycia N. Carey             */
/* Parts of code borrowed from:        */
/* demo-simple-exmple.cpp              */
/* final velocity = V_i + at   m/s     */
/***************************************/

#include "palisade.h"
#include "math/matrix.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>

using namespace std;
using namespace lbcrypto;

// void print(Plaintext v, int length)
// {

//     int print_size = 20;
//     int end_size = 2;

//     cout << endl;
//     cout << "    [";

//     for (int i = 0; i < print_size; i++)
//     {
//         cout << setw(3) << right << v->GetPackedValue()[i] << ",";
//     }

//     cout << setw(3) << " ...,";

//     for (int i = length - end_size; i < length; i++)
//     {
//         cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
//     }
    
//     cout << endl;
// }
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
    int N = 8192; //2760 8192 16384 32768
	vector<int64_t> initial_velocity; //vector<int64_t> initial_velocity={1,2,3,4,5,6,7,8,9,1}; 
	vector<int64_t> times; //vector<int64_t> times= {10,14,24,23,18,9,13,7,9,1}; 
	vector<int64_t> acc;  //vector<int64_t> acc={1,2,3,2,1,2,1,2,9,1}; 
	vector<double>  N_mean;

	for(int i = 0; i < N; i++)
	{
		int64_t a = rand() % 1000 + 1;
		acc.push_back(a);

		int64_t b = rand() % 1000 + 1;
		initial_velocity.push_back(b);

		int64_t c = rand() % 1000 + 1;
		times.push_back(c);

		double  d = rand() % 1000 + 1;
		N_mean.push_back(1/d); //linear regression
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

	auto enc_acc_mult_times = cryptoContext->EvalMult(enc_acc, enc_times);                  //a*t
	auto enc_final_vel = cryptoContext->EvalAdd(enc_initial_vel, enc_acc_mult_times);			//V_i + at
	// //Test advance operations
	//auto enc_final_vel_sum = cryptoContext->EvalSum(enc_final_vel, N);
	//cout << "enc_final_vel_sum: " << enc_final_vel_sum << endl;
	//print(enc_final_vel_sum,N);
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

	// //EvalMultiMany
	// auto enc_final_vel_MultMany = cryptoContext->EvalMultMany(enc_final_vel, enc_final_vel);
	// Plaintext plain_final_velocity_MultMany ;
	// cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel_MultMany , &plain_final_velocity_MultMany);

	// //EvalMerge
	// auto enc_final_vel_Merge = cryptoContext->EvalMerge(enc_final_vel, enc_final_vel);
	// Plaintext plain_final_velocity_Merge;
	// cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel_Merge, &plain_final_velocity_Merge);
	
	//testing Linear regression
	// double find_coef(CipherText_X,CipherText_Y,N)
	// {
	// 	auto X_mean = EvalSum(CipherText_X, N);
	// 	auto Y_mean = EvalSum(CipherText_Y, N);
	// 	X_mean=X_mean[0]/N; //Calculate x mean value
	// 	Y_mean=Y_mean[0]/N; //Calculate y mean value
	// 	{
	// 		auto SS_XY = cc->EvalInnerProduct(CipherText_X, CipherText_Y, N);
	// 		SS_XY=SS_XY-N*X_mean*Y_mean;
	// 	}
	// 	{
	// 		auto SS_XX = cc->EvalInnerProduct(CipherText_X, CipherText_X, N);
	// 		SS_XX=SS_XX-N*X_mean*X_mean;
	// 	}
	// 	std::cout<< "SS_xy : " << SS_XY <<std::endl;
	//     std::cout<< "SS_xx : " << SS_XX <<std::endl;
	//     std::cout<< "X_mean : " << X_mean <<std::endl;
	//     std::cout<< "Y_mean : " << Y_mean <<std::endl;
	//     return
	//     B_1 =  SS_XY / SS_XX;
	//     B_0 =  Y_mean - B_1 * X_mean ;
	// }
	// auto X_mean = cryptoContext->EvalSum(enc_acc, N);
	// auto Y_mean = cryptoContext->EvalSum(enc_initial_vel, N);
	// //Eval X_mean and Y_mean 
	// X_mean = cryptoContext->EvalMult(X_mean, enc_N_mean);
	// Y_mean = cryptoContext->EvalMult(Y_mean, enc_N_mean);
	// //Eval S_XX and SXY
	// S_XX = cryptoContext->EvalInnerProduct(enc_acc,enc_acc,N);
	// S_XY = cryptoContext->EvalInnerProduct(enc_acc,enc_initial_vel,N);
	// //n
	// //SS_xx = SS_xx - n * X_mean * X_mean;
	// S_XX = SS_XX - 


	//cout << "X_mean " << X_mean << endl;

	// print(X_mean,N);
	// print(Y_mean,N);
	// print(plain_final_velocity_MultMany ,N);
	// print(plain_final_velocity_Merge,N);

	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;

	cout << "Acceleration: " << endl;
	print(plain_acc, N);

	cout << "Initial Velocity: " << endl;
	print(plain_initial_vel, N);

	cout << "Time: " << endl;
	print(plain_times, N);

	cout << " Final Velocity: " << endl;
	print(plain_final_velocity, N);
	//std::cout << "initial_velocity \n\t" << plain_initial_vel << std::endl;
	//print(initial_velocity, num_slots);

	//std::cout << "time \n\t" << plain_times << std::endl;
	//print(times, num_slots);

	//std::cout << "Acceleration \n\t " << plain_acc << std::endl;
	//print(acc, num_slots);

	//cout << "Final Velocity: " << endl;
	//std::cout << "final_vel \n\t" << plain_final_velocity << std::endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	cout << "eval_sum_clock        : " << ((float)eval_sum_clock)/CLOCKS_PER_SEC << endl;
	cout << "dec_sum_clock         : " << ((float)dec_sum_clock)/CLOCKS_PER_SEC << endl;
	cout << "eval_IP_clock         : " << ((float)eval_IP_clock)/CLOCKS_PER_SEC << endl;
	cout << "dec_IP_clock          : " << ((float)dec_IP_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
