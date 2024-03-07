#include "sigmoid_ckks.h"


std::vector<double> coeff({ 0.5000000000000107, 0.17209906934813146, 0.0, -0.0029501761301167426, 0.0, 2.6262363172485713e-05, 0.0, -1.1845866975589415e-07, 0.0, 2.801559311285922e-10, 0.0, -3.3145939768213955e-13, 0.0, 1.546695810026845e-16}); //This gives 96.60 (96.5955) accuracy 
  
  
SigmoidCKKS::SigmoidCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                         std::string rotKeyLocation,
                         std::string inputLocation,
                         std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation),
      m_MultKeyLocation(multKeyLocation),
      m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation),
      m_InputLocation(inputLocation),
      m_OutputLocation(outputLocation)
{
    initCC();
};

void SigmoidCKKS::initCC()
{
    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::JSON))
    {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY))
    {
        std::cerr << "Could not deserialize public key file" << std::endl;
        std::exit(1);
    }

    std::ifstream multKeyIStream(m_MultKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open())
    {
        std::exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize rot key file" << std::endl;
        std::exit(1);
    }

    std::ifstream rotKeyIStream(m_RotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open())
    {
        std::exit(1);
    }

    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_InputLocation, m_InputC, SerType::BINARY))
    {
        std::exit(1);
    }
}

void SigmoidCKKS::eval()
{
	std::cout << "we are in eval \n" << std::endl<<std::endl;
	m_cc->Enable(ADVANCEDSHE);
          
    auto c_x1 = m_InputC;
    auto c_x2 = m_cc->EvalMult(c_x1,c_x1);
    auto c_x3 = m_cc->EvalMult(c_x1,c_x2);
    auto c_x4 = m_cc->EvalMult(c_x2,c_x2);
    auto c_x5 = m_cc->EvalMult(c_x2,c_x3);
    
    auto g_t=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(1.0e-03)),c_x1);//2
    auto g_t1=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(coeff[9]*pow(10,6))),c_x1);//2

    auto g_t2=m_cc-> EvalSquare(g_t);//3 x^4
    auto g_t3=m_cc->EvalMult(g_t1,c_x3);//3 x^5
    
    auto e_t=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(1.0e-05)),c_x2);//2
    auto e_t1=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(coeff[11]*pow(10,10))),c_x1);//2

    auto e_t2=m_cc-> EvalSquare(e_t);//3 x^6
    auto e_t3=m_cc->EvalMult(e_t1,c_x3);//3 x^5
    
    
    auto f_t=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(1.0e-06)),c_x2);//2
    auto f_t1=m_cc->EvalMult(m_cc->EvalMult(c_x1,(double)(coeff[13]*pow(10,12))),c_x2);//2

    auto f_t2=m_cc-> EvalSquare(f_t);//3 x^6
    auto f_t3=m_cc->EvalMult(f_t1,c_x4);//3 x^7
    
    
    auto eval_1 = m_cc->EvalAdd(m_cc->EvalMult(c_x1,coeff[1]),coeff[0]);
    auto eval_2 = m_cc->EvalAdd(m_cc->EvalMult(m_cc->EvalMult(c_x2,coeff[3]),c_x1),eval_1);

    auto eval_3 = m_cc->EvalAdd(m_cc->EvalMult(m_cc->EvalMult(c_x3,coeff[5]),c_x2),eval_2);
    auto eval_4 = m_cc->EvalAdd(m_cc->EvalMult(m_cc->EvalMult(c_x4,coeff[7]),c_x3),eval_3);
    auto eval_5 = m_cc->EvalAdd(m_cc->EvalMult(g_t2,g_t3),eval_4);
    auto eval_6 = m_cc->EvalAdd(m_cc->EvalMult(e_t2,e_t3),eval_5);
    auto eval_7 = m_cc->EvalAdd(m_cc->EvalMult(f_t2,f_t3),eval_6);
    
    m_OutputC = eval_7;


}

void SigmoidCKKS::deserializeOutput()
{
    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }
}
