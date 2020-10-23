/* Code refer to the linregress.cpp*/

#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "palisade.h"

#include "math/matrix.h"

using namespace std;
using namespace lbcrypto;

void ArbBGVLinearRegressionPackedArray();
void ArbBFVLinearRegressionPackedArray();

template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
};

int main() {
  std::cout << "\nThis code demonstrates the use of packing for linear "
               "regression using the BGV and BFV schemes. "
            << std::endl;
  std::cout
      << "This code shows how parameters can be manually set in our library. "
      << std::endl;

  std::cout
      << "\n===========BGV TESTS (LINEAR-REGRESSION-ARBITRARY)===============:            "
      << "Return the parameter vector using (x^T x)^{-1} x^T y (using least squares method"
      << std::endl;

  ArbBGVLinearRegressionPackedArray();

  // std::cout
  //     << "\n===========BFV TESTS (INNER-PRODUCT-ARBITRARY)===============: "
  //     << std::endl;

  // ArbBFVLinearRegressionPackedArray();

  // std::cout << "Please press any key to continue..." << std::endl;

  // std::cin.get();
  return 0;
}

void ArbBGVLinearRegressionPackedArray() {
  PackedEncoding::Destroy();

  usint m = 22;
  // usint p = 524591;
  PlaintextModulus p = 2333;
  BigInteger modulusP(p);
  /*BigInteger modulusQ("577325471560727734926295560417311036005875689");
  BigInteger
  squareRootOfRoot("576597741275581172514290864170674379520285921");*/
  // BigInteger modulusQ("955263939794561");
  // BigInteger squareRootOfRoot("941018665059848");
  BigInteger modulusQ("1267650600228229401496703214121");
  BigInteger squareRootOfRoot("498618454049802547396506932253");
  // BigInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
  // std::cout << squareRootOfRoot << std::endl;

  // BigInteger bigmodulus("80899135611688102162227204937217");
  // BigInteger bigroot("77936753846653065954043047918387");
  BigInteger bigmodulus(
      "1645504557321206042154969182557350504982735865633579863348616321");
  BigInteger bigroot(
      "201473555181182026164891698186176997440470643522932663932844212");
  // std::cout << bigroot << std::endl;

  auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly,
                                                                  modulusQ);

  float stdDev = 4;

  usint batchSize = 8;

  auto params = std::make_shared<ILParams>(m, modulusQ, squareRootOfRoot,
                                           bigmodulus, bigroot);

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(
      p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

  PackedEncoding::SetParams(m, encodingParams);

  CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(
      params, encodingParams, 8, stdDev, OPTIMIZED);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  std::cout << "Starting key generation" << std::endl;

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  // Compute evaluation keys
  cc->EvalSumKeyGen(kp.secretKey);
  cc->EvalMultKeyGen(kp.secretKey);

  auto zeroAlloc = [=]() { return cc->MakePackedPlaintext({0}); };

  Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, 2);

  // xP(0, 0) = cc->MakePackedPlaintext({0, 2, 1, 3, 2, 2, 1, 2});
  // xP(0, 1) = cc->MakePackedPlaintext({1, 1, 2, 1, 1, 1, 3, 2});
  xP(0, 0) = cc->MakePackedPlaintext({0, 2, 4, 6, 8, 10, 12, 14});
  xP(0, 1) = cc->MakePackedPlaintext({1, 1, 1, 1, 1, 1, 1, 1});
  //xP(0, 1) = cc->MakePackedPlaintext({100, 100, 100, 100, 100, 100, 100, 100});

  std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
  std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

  //Matrix operation example
  //Linear regression
  //Multiple Linear regession

  Matrix<Plaintext> yP = Matrix<Plaintext>(zeroAlloc, 2, 1);

  yP(0, 0) = cc->MakePackedPlaintext({0, 1, 2, 3, 4, 5, 6, 7});
  std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  std::cout << "Starting encryption of x" << std::endl;

  shared_ptr<Matrix<RationalCiphertext<Poly>>> x =
      cc->EncryptMatrix(kp.publicKey, xP);

  std::cout << "Starting encryption of y" << std::endl;

  shared_ptr<Matrix<RationalCiphertext<Poly>>> y =
      cc->EncryptMatrix(kp.publicKey, yP);

  ////////////////////////////////////////////////////////////
  // Linear Regression
  ////////////////////////////////////////////////////////////
  //return the parameter vector using (x^T x)^{-1} x^T y (using least
  //* squares method



  auto result = cc->EvalLinRegressBatched(x, y,8);

  //////////////////////////////////////////////////////////
  //Decryption
  //////////////////////////////////////////////////////////

  shared_ptr<Matrix<Plaintext>> numerator;
  shared_ptr<Matrix<Plaintext>> denominator;

  cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

  std::cout << (*numerator)(0, 0)->GetPackedValue()[0] << ","
            << (*numerator)(1, 0)->GetPackedValue()[0] << std::endl;
  std::cout << (*denominator)(0, 0)->GetPackedValue()[0] << ","
            << (*denominator)(1, 0)->GetPackedValue()[0] << std::endl;
}

