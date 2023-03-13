#pragma once

#include "Utils.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <cstdlib>
#include <array>
#include <deque>
#include <map>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/crc.hpp>

using boost::asio::ip::tcp;

typedef std::array<char, UUID_SIZE> uuid;
typedef std::array<char, PUB_KEY_SIZE> pubKey;
typedef std::array<char, SYMMETRIC_KEY_SIZE> symKey;


class Client
{
private:

    void get_Transfer_Info();
    void send_regesstration_requet();
    std::string send_public_key();
    uint32_t send_file_request(std::string symmetricKey, std::string filePath);
    uint32_t calculate_CRC(const std::string& myString);
    void CRC_succses();
    void CRC_failed();
    void CRC_failed_four_times();
    void get_Client_ID();
    std::string get_file_content(std::string filename);
    
    
    std::ofstream open_Out_File(const std::string filename);
    std::ifstream open_In_File(const std::string filename);
    std::vector<char> build_Header(char* clientId, char version, uint16_t code, uint32_t size);
    //std::vector<char> build_payload(char* destClientID, uint8_t msgType, uint32_t size);
    std::vector<char> build_file_payload(char* clientId, uint32_t contentSize, std::string fName, std::string encFile);
    std::vector<char> build_CRC_payload(char* clientID, std::string fName);


    /*  tcp ip  */
    boost::asio::ip::address ip_;
    uint16_t port_;

    /*  user information and keys */
    std::string username_ = "";
    std::string filepath_ = "";
    std::string filename_ = "";
    std::string privateKey_ = "";
    std::string base64Pivatekey = "";
    std::string symmetricKey_ = "";
    

    uuid clientID_ = { 0 };
    std::string  symmetricKey;
    /*  session variables   */
    char buffer_data[CHUNK_SIZE] = { 0 };
    uint16_t status = 0;


    /*  session objects     */
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    boost::system::error_code err;
    RSAPrivateWrapper* rsapriv_ = nullptr; // RSA private/public key pair engine and decryptor
    RSAPublicWrapper* rsapub_ = nullptr;   // RSA encryptor with public key
    RSAPrivateWrapper* dec_rsapriv_ = nullptr; // RSA decryptor with private key 


    /*  send and recive from socket */
    size_t send_bytes(char* data, size_t amount);
    size_t send_bytes(std::vector<char> vec, size_t amount);
    size_t send_bytes(std::string str, size_t amount);
    size_t recive_bytes(size_t amount);

    std::string convert_to_string(char* buffer);
    
    void clear_buffer(char* buf, uint32_t size);
    void parse_response_header(ResponseHeader* rh, char* arr);

    void hexify(const unsigned char* buffer, unsigned int length);
    std::string hex2Ascii(const char* arr, size_t len);
    void ascii2HexBytes(char* dest, const std::string src, size_t len);
   

public:

    Client() = default;
    Client(boost::asio::io_context& io_context);
    ~Client();

    void prosess_requsts();
    void connect_to_server();
    void close_connection();
    char version_ = 3;
    
};

