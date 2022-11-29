#include <cstdio>

#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <openssl/evp.h>

namespace
{
    constexpr unsigned char KEY[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    constexpr unsigned char IV[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

    class CryptoppBench
    {
    private:
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        std::vector<unsigned char> output;

    public:
        CryptoppBench()
        {
            enc.SetKeyWithIV(KEY, sizeof(KEY), IV);
        }

        unsigned encrypt_sum(const std::vector<unsigned char> &input)
        {
            output.resize(input.size() + 16);
            enc.EncryptAndAuthenticate(output.data(), output.data() + input.size(), 16,
                                       IV, sizeof(IV), nullptr, 0, input.data(), input.size());
            unsigned result = 0;
            for (auto c : output)
            {
                result += c;
            }
            return result;
        }
    };
}

int main()
{
    std::vector<unsigned char> input(1 << 30, 233);
    printf("Sum %u\n", CryptoppBench().encrypt_sum(input));
    return 0;
}
