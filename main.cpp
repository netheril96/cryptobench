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

    class OpenSSLBench
    {
    private:
        EVP_CIPHER_CTX *ctx = nullptr;
        std::vector<unsigned char> output;

    public:
        OpenSSLBench()
        {
            ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                abort();
            }
            EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), nullptr, KEY, IV, 1);
        }
        ~OpenSSLBench()
        {
            EVP_CIPHER_CTX_free(ctx);
        }
        OpenSSLBench(OpenSSLBench &&) = delete;

        unsigned encrypt_sum(const std::vector<unsigned char> &input)
        {
            output.resize(input.size() + 16);
            int outlen = input.size();
            EVP_CipherUpdate(ctx, output.data(), &outlen, input.data(), input.size());
            EVP_CipherFinal(ctx, output.data() + outlen, &outlen);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, output.data() + input.size());
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
    printf("Sum %u\n", OpenSSLBench().encrypt_sum(input));
    return 0;
}
