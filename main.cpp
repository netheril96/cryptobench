#include <iostream>
#include <chrono>

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
        unsigned char iv[12];

    public:
        CryptoppBench()
        {
            memcpy(iv, IV, 12);
            enc.SetKeyWithIV(KEY, sizeof(KEY), IV);
        }

        unsigned encrypt_sum(const std::vector<unsigned char> &input)
        {
            iv[0]++;
            output.resize(input.size() + 16);
            enc.EncryptAndAuthenticate(output.data(), output.data() + input.size(), 16,
                                       iv, sizeof(iv), nullptr, 0, input.data(), input.size());
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
        unsigned char iv[12];

    public:
        OpenSSLBench()
        {
            memcpy(iv, IV, 12);
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
            iv[0]++;
            EVP_CipherInit_ex(ctx, nullptr, nullptr, nullptr, iv, 1);
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

    template <class Func>
    std::chrono::high_resolution_clock::duration bench(const Func &func, int iterations)
    {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            func();
        }
        auto finish = std::chrono::high_resolution_clock::now();
        return finish - start;
    }
}

int main()
{
    std::vector<unsigned char> input(1 << 30, 233);
    CryptoppBench cb;
    OpenSSLBench ob;
    std::cout << cb.encrypt_sum(input) << '\n'
              << ob.encrypt_sum(input) << "\n\n";

    unsigned long long osum = 0, csum = 0;

    std::cout << "OpenSSL timing: " << bench([&]()
                                             { osum += ob.encrypt_sum(input); },
                                             10)
                                               .count() *
                                           1e-6
              << "ms\n";

    std::cout << "CryptoPP timing: " << bench([&]()
                                              { csum += cb.encrypt_sum(input); },
                                              10)
                                                .count() *
                                            1e-6
              << "ms\n";

    std::cout << "OpenSSL total: " << osum << "\nCryptoPP total: " << csum << '\n';

    return 0;
}
