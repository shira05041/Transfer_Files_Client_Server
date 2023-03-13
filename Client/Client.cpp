#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <stdio.h>
#include "Client.h"
#include "Utils.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <array>
#include <vector>


using boost::asio::ip::tcp;


/*
*Client constructor.
*The constructor reads the transfer info and obtain its information regarding the client.
*/
Client::Client(boost::asio::io_context & io_context) : io_context_(io_context), socket_(io_context)
{
	get_Transfer_Info();

}


Client::~Client()
{

}


/*
* This function reads the transfer info from the file "transfer.info".
* The info contains server's ip and port, clients user name, and the path to the file to be sent to server.
* The function checks if all info is valid and assigns to class members.
*/
void Client::get_Transfer_Info()
{
	std::string line = "";
	std::string port = "";
	std::string ip = "";
	std::string filepath = "";
	size_t pos;


	std::ifstream transInfo(TRANSFER_INFO);
	if(!transInfo) //check if file does not exist
		throw std::exception("transfer.info file does not exist");

	// attempt to open the file and read the info, get the ip and port
	std::ifstream file = open_In_File(TRANSFER_INFO);

	std::getline(file, line); //read ip and port from file

	if (line.size() == 0) 
	{
		file.close();
		throw std::exception("'transfer.info' file is empty");
	}

	// take out the ip and port substrings
	pos = line.find(":");
	if (pos != std::string::npos)
	{
		ip = line.substr(0, pos);
		port = line.substr(pos + 1);
	}
  
	// check whether the ip and port are valid
	if (port.size() > 0 && port.size() <= 4)
		port_ = std::stoi(port);  // assign to class member 
	else
	{
		file.close();
		throw std::exception("Invalid port number");
	}

	boost::asio::ip::address ip_add = boost::asio::ip::make_address(ip);
	if (!ip_add.is_v4())
	{
		file.close();
		throw std::exception("Invalid ip address");
	}

	ip_ = ip_add; // assign to class member

	// client username
	std::getline(file, line);
	if (line.size() == 0 || line.size() > MAX_USERNAME)
	{
		file.close();
		throw std::exception("username is not valied in 'tansfer.info' file");
	}
	username_ = line;  // assign to class member

	// read filepath
	std::getline(file, line);
	
	std::ifstream file_Path(line);
	if (!file_Path) //if file path we wanted to send to server is not found
	{
		file.close();
		throw std::exception("file path does not exist");
	}
	filepath_ = line;  // assign to class member
	filename_ = filepath_;
	/*//get the file name from file path
	pos = filepath_.find(".");
	int i = filepath_.find_last_of("/ \\");
	if (pos != std::string::npos && i != std::string::npos)
	{
		filename_ = line.substr(i + 1, pos);
	}*/

    std::cout << "IP:  " << ip << " Port:  " << port << " User Name:  " << username_ << " File Name:  " 
										<< filename_ << " File Path:  " << filepath_ << std::endl;

	file.close(); //finished handling eith 'transfer.info' file. All the information was valid
}


/*
* this function handles the process of the client's requests from the server
*/
void Client::prosess_requsts()
{
	std::string file_content = get_file_content(filename_);
	uint32_t client_CRC;
	uint32_t server_CRC;
	std::string dec_file = "";
	bool isEqual = FALSE;
	try
	{
		std::ifstream file;
		file.open(ME_INFO);
		std::cout << "in prosess_requsts function" << std::endl;
		if (!file) //check if me.info does not exist, which means the user does not registered
			send_regesstration_requet();
		else
		{
			std::cout << "User already registered" << std::endl;
			get_Client_ID();
			connect_to_server(); //connect to server
		}

		symmetricKey_ = send_public_key();//send public key to server and get AES key encrypted with the public key we sent.

		for (int i = 0; i < SEND_TIMES; ++i)
		{
			std::cout << "file sent "<< i+1<< " times " << std::endl;

			client_CRC = calculate_CRC(file_content);
			//client_CRC = calculate_CRC("1234");//just for check
			server_CRC = send_file_request(symmetricKey, filename_);
			
			if (server_CRC != client_CRC)
				CRC_failed();
			else
			{
				isEqual = TRUE;
				break;
			}
		}
		if (isEqual)  //client_CRC and server_CRC were equal
		{ 
			std::cout << "CRC are equals!!!!!!!" << std::endl;
			CRC_succses();
		}

		else
			CRC_failed_four_times();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
}

/*
* this function 
 */
void Client::send_regesstration_requet()
{
	/* construct request header and paylod  */
	std::vector<char>header = build_Header(clientID_.data(), version_, REGISTER_CODE, MAX_USERNAME);
	connect_to_server();

	send_bytes(header, HEADER_SIZE); //send request header

	std::vector<char> payload(username_.c_str(), username_.c_str() + MAX_USERNAME);// convert string username to bytes vector
	/*in order to prevent access to invalid hidden data, we padd the user name to fill max user name length*/
	std::vector<char>::iterator it;
	it = payload.end();
	payload.insert(it, MAX_USERNAME - payload.size(), NULL);
	
	//socket_.connect(tcp::endpoint(ip_, port_));
	 
	send_bytes(payload.data(), MAX_USERNAME); //send request payload

	/* receive response from server */
	// receive header
	recive_bytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parse_response_header(resHead, buffer_data);

	if (resHead->statusCode == REGISTER_FAILED)
	{
		delete(resHead);
		throw std::exception("Regestration failed, User already exists");
	}

	if (resHead->payloadSize != UUID_SIZE)
	{
		delete(resHead);
		throw std::exception("Invalid payload size.");
	}
		
	std::cout << "Server status code: " << resHead->statusCode << std::endl;

	
	if (resHead->statusCode != REGISTER_SUCCESS)
	{
		delete(resHead);
		throw std::exception("Invalid server satus code.");
	}	
	else
	{	// receive payload
		recive_bytes(UUID_SIZE);
		memcpy(clientID_.data(), buffer_data, UUID_SIZE);//insert into clientID_ (member class) the client id recieved
		std::cout << "UUID: "; hexify((unsigned char*)clientID_.data(), UUID_SIZE); std::cout << std::endl;
		std::cout << "ID: " << clientID_.data() << std::endl;
		delete(resHead);

		/* save to me.info */
		std::ofstream me_file = open_Out_File(ME_INFO);
		std::cout << "Creating: " << ME_INFO << std::endl;
		me_file << username_ << std::endl;
		me_file << hex2Ascii(clientID_.data(), UUID_SIZE) << std::endl;
		//me_file << privateKey_ << std::endl;
		me_file.close();
	}
}

/*
* This function  sends the clients public key to server, and recieves AES key encoded by the public key.
*the request includes a header and a payload consisting of the clients user name and public key
*/
std::string Client::send_public_key()
{
	std::array<char, SYMMETRIC_KEY_SIZE> symetricKey;
	RSAPrivateWrapper rsapriv;
	std::string pubkey = rsapriv.getPublicKey(); //get the public key
	std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());//get the private key and encode it as base64
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));
	

	/* create request header and payload */
	std::vector<char>header = build_Header(clientID_.data(), version_, PUBLIC_CODE, MAX_USERNAME + PUB_KEY_SIZE);
	// convert string username to bytes vector 
	std::vector<char> payload(username_.c_str(), username_.c_str() + MAX_USERNAME);
	/*in order to prevent access to invalid hidden data, we padd the user name to fill max user name length*/
	std::vector<char>::iterator it;
	it = payload.end();
	payload.insert(it, MAX_USERNAME - payload.size(), NULL);

	// send header and paylpad
	send_bytes(header, HEADER_SIZE);
	send_bytes(payload.data(), MAX_USERNAME);
	send_bytes(pubkey, PUB_KEY_SIZE);
	std::cout << "public key:" << std::endl;
	hexify((unsigned char*)pubkey.c_str(), pubkey.length());	// print binary data nicely
	std::cout << "Public key size: " << pubkey.length() << std::endl;

	/* receive response from server */
	// receive header
    recive_bytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parse_response_header(resHead, buffer_data);

	if (resHead->statusCode != RECIVE_AES_KEY)
	{
		delete(resHead);
		throw std::exception("Invalid status code");
	}
	else
	{
		//recieve payload
		recive_bytes(UUID_SIZE);//insert into data buffer the client id recieved
		recive_bytes((resHead->payloadSize) - UUID_SIZE);//insert into data buffer the aes key recieved
		std::cout << "encripted AES :" << std::endl;
		hexify((unsigned char*)buffer_data, sizeof(buffer_data));
	
		std::string cipher = convert_to_string(buffer_data);
		std::cout << "cipher len = " << cipher.length() << std::endl;
		std::string decrypted = rsapriv_other.decrypt(cipher);		
		std::cout << "decrypted AES:" << std::endl;
		hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely
		
		delete(resHead);
		return decrypted;
	}
}


uint32_t Client::send_file_request(std::string symmetricKey, std::string filename_)
{
	std::cout << "in send_file_request function: " << std::endl;
	std::string encrypted_file;// encrypted file
	uint32_t server_CRC = 0;

	std::ifstream file(filename_, std::ios::binary);
	file.seekg(0, std::ios::end);
	uint32_t  file_size = file.tellg();
	std::cout << "Size of file before decryption: " << " " << file_size << " bytes" << std::endl;

	// create encryption engine
	AESWrapper aes((unsigned char*)symmetricKey.data(), SYMMETRIC_KEY_SIZE);

	std::string content = get_file_content(filename_);

	encrypted_file = aes.encrypt(content.c_str(), content.length()); //encrypted_file contains  - encrypted content file
	uint32_t encFile_size = file_size + (BLOCK_SIZE - (file_size % BLOCK_SIZE)); //calculate the file size after encryption.
	std::cout << "encrypted_file size:" << encFile_size << std::endl;
	std::cout << "Encrypted_file:" << std::endl;
	hexify(reinterpret_cast<const unsigned char*>(encrypted_file.c_str()), encrypted_file.length());
	
	/* construct request header and message payload */
	std::vector<char>header = build_Header(clientID_.data(), version_, SEND_FILE_CODE, UUID_SIZE + CONTENT_SIZE + MAX_FILENAME + encFile_size);
	std::vector<char> payload = build_file_payload(clientID_.data(), encFile_size,	filename_, encrypted_file);
		
	/*send request header and message pyload*/
	send_bytes(header, HEADER_SIZE);
	send_bytes(payload, payload.size());
	
	
	/* receive response from server */ 
	// receive header
	recive_bytes(HEADER_SIZE_RESPONSE);
	
	ResponseHeader* resHead = new ResponseHeader;
	
	parse_response_header(resHead, buffer_data);
	
	std::cout << "Server status code: " << resHead->statusCode << std::endl;

	if (resHead->statusCode != RECIVE_CRC_CODE)
	{
		delete(resHead);
		throw std::exception("Invalid status code");
	}
		

		//recieve payload
		recive_bytes(UUID_SIZE + CONTENT_SIZE + MAX_FILENAME);//not interested
		recive_bytes(CRC_SIZE);//recieve server crc calculation
		
		server_CRC = (uint8_t)(buffer_data[0]) |
		(uint8_t)(buffer_data[1]) << 8 |
		(uint8_t)(buffer_data[2]) << 16 |
		(uint8_t)(buffer_data[3]) << 24;

		
		std::cout << "server crc: " << server_CRC << std::endl;
	
	delete(resHead);
	return server_CRC;
}


void Client::get_Client_ID()
{   
	std::string line;
	std::ifstream infoFile(ME_INFO);
	if (!infoFile)//check if file doesn't exist
		throw std::exception("In function getClientID, me.info file does not exist");

	/* attempt to open the fileand read the client id*/
	std::ifstream file;
	file = open_In_File(ME_INFO);
	std::getline(file, line);//read name
	std::getline(file, line);//read client ID

	if (line.size() == 0) {
		file.close();
		throw std::exception("In function getClientID, Couldn't get client ID");
	}
	ascii2HexBytes(clientID_.data(), line, UUID_SIZE);
	std::cout << "Client ID:" << std::endl;
	hexify(reinterpret_cast<const unsigned char*>(clientID_.data()), clientID_.size());

}


//this function reads the file content into a string
std::string Client::get_file_content(std::string filename)
{
	std::string content;

	std::ifstream file = open_In_File(filename);

	while (!file.eof())
	{
		std::getline(file, content);
	}
	std::cout << "CONTENT FILE: \n" << content << std::endl;
	return content;
}


/*
* this function calculate the file CRC before the encryption
*/
uint32_t Client::calculate_CRC(const std::string& myString)
{
	boost::crc_32_type result;
	result.process_bytes(myString.data(), myString.length());
	std::cout << "client CRC: " << result.checksum()<< std::endl;
	return result.checksum();
}

/*
* this function handle the procces when the CRC of client and server are equals
*/
void Client::CRC_succses()
{
	/* construct request header and send */
	std::vector<char>header = build_Header(clientID_.data(), version_, CRC_SUCCSES, UUID_SIZE + MAX_FILENAME);
	std::vector<char>crcPayload = build_CRC_payload(clientID_.data(), filepath_);

	// send header and payload to server
	send_bytes(header, HEADER_SIZE);
	send_bytes(crcPayload, UUID_SIZE + MAX_FILENAME);
	std::cout << "crcPayload size: " << crcPayload.size() << std::endl;
	// receive header
	recive_bytes(HEADER_SIZE_RESPONSE);
	ResponseHeader* resHead = new ResponseHeader;
	parse_response_header(resHead, buffer_data);

	if (resHead->statusCode != RECIVED_MSG_THANK_YOU) {
		delete(resHead);
		throw std::exception("Invalid status code");
	}
	else
	{
		std::cout << "File " << filepath_ << " has been sent successfully!" << std::endl;
		std::cout << "---CLOSEING CONNECTION!!---" << std::endl;
		close_connection();
	}
	std::cout << "Server status code: " << resHead->statusCode << std::endl;
	std::cout << "File " << filepath_ << " was successfully received by server" << std::endl;
}


/*
* this function handle the procces when the CRC of client and server are not equals
*/
void Client::CRC_failed()
{
	/* construct request header and send */
	std::vector<char>header = build_Header(clientID_.data(), version_, CRC_FAILED, UUID_SIZE + MAX_FILENAME);
	std::vector<char>crcPayload = build_CRC_payload(clientID_.data(),filepath_);

	send_bytes(header, HEADER_SIZE);// send header
	
}


/*
* this function handle the procces when the CRC of client and server are not equals for 3 times
*/
void Client::CRC_failed_four_times()
{
	/* construct request header and send */
	std::vector<char>header = build_Header(clientID_.data(), version_, CRC_FAILED_FOUR_TIMES, UUID_SIZE + MAX_FILENAME);
	std::vector<char>payload = build_CRC_payload(clientID_.data(), filepath_);
	
	send_bytes(header, HEADER_SIZE); // send header
	send_bytes(payload, UUID_SIZE + MAX_FILENAME); // send payload - clientId, file name

	std::cout << "Sending the file to the server failed!" << std::endl;
	std::cout << "---CLOSEING CONNECTION!!---" << std::endl;
	close_connection();
}


/*
* This function returns a message payload vector according to the given parameters
* and according to protocol.
* Notice that we do not refer to the actual content.
* The content will be sent afterwards.
*   clientid    uuid 16 byte
*	fname		file name 255 byte
*/
std::vector<char> Client::build_CRC_payload(char* clientID, std::string fName)
{
	std::vector<char> crcPayload;
	
	for(size_t i = 0; i < UUID_SIZE; ++i)
		crcPayload.push_back((uint8_t)clientID_[i]);

	size_t size = fName.length();
	// convert string file name to bytes vector 
	std::vector<char> fileName(fName.c_str(), fName.c_str() + MAX_FILENAME);
	/*in order to prevent access to invalid hidden data, we padd the file name to fill max file name length*/
	std::vector<char>::iterator it;
	it = fileName.end();
	fileName.insert(it, MAX_FILENAME - size, NULL);

	for (size_t i = 0; i < MAX_FILENAME; i++)//insert fileName into payload
		crcPayload.push_back((uint8_t)fileName[i]);

	std::cout << "crcPayload size: " << crcPayload.size()<< std::endl;
	return crcPayload;
}

/*
* this function open a file for output - write
*/
std::ofstream Client::open_Out_File(const std::string filename)
{
	std::ofstream file;
	file.open(filename);
	if (!file) 
	{
		std::cout << "Error in file: " << filename << ". ";
		throw std::exception("File does not exist");
	}
	return file;
}
	
/*
* this function opens a file for input - read
*/
std::ifstream Client::open_In_File(const std::string filename)
{
	std::ifstream file;
	file.open(filename);
	if (!file)
	{
		std::cout << "Error in file: " << filename << ". ";
		throw std::exception("File does not exist");
	}
		
	return file;
}



/*
* this function builds and returns the client header vector according to the given parameters and protocol.
*	   clientId        16 byte
*	   version         1 bytes
*	   status code     2 bytes
*	   size payload    4 bytes
*/
std::vector<char> Client::build_Header(char* clientId, char version_, uint16_t code, uint32_t size)
{
	std::vector<char> header;

	for (size_t i = 0; i < UUID_SIZE; i++)//insert client id into header
		header.push_back((uint8_t)clientId[i]);

	header.push_back(version_); // insert version into header

	header.push_back((uint8_t)(code)); // insert status code into header
	header.push_back((uint8_t)(code >> 8));

	header.push_back((uint8_t)(size));//insert payload size into haeder
	header.push_back((uint8_t)(size >> 8));
	header.push_back((uint8_t)(size >> 16));
	header.push_back((uint8_t)(size >> 24));

	return header;
}


/*
* this function builds and returns the file payload vector according to the given parameters and protocol.
*	   clientId        16 byte
*	   content size    4 bytes
*	   file name       255 bytes
*	   content file    variable  		
*/
std::vector<char> Client::build_file_payload(char* clientId, uint32_t contentSize, std::string fName, std::string encFile)
{
	std::vector<char> filePayload;

	for (size_t i = 0; i < UUID_SIZE; i++)//insert clientId into payload
		filePayload.push_back((uint8_t)clientId[i]);

	filePayload.push_back((uint8_t)(contentSize));//insert content size into payload
	filePayload.push_back((uint8_t)(contentSize >> 8));
	filePayload.push_back((uint8_t)(contentSize >> 16));
	filePayload.push_back((uint8_t)(contentSize >> 24));

	size_t size = fName.length();
	// convert string file name to bytes vector 
	std::vector<char> fileName(fName.c_str(), fName.c_str() + MAX_FILENAME);
	/*in order to prevent access to invalid hidden data, we padd the file name to fill max file name length*/
	std::vector<char>::iterator it;
	it = fileName.end();
	fileName.insert(it, MAX_FILENAME - size, NULL);
	
	for (size_t i = 0; i < MAX_FILENAME; i++)//insert fileName into payload
		filePayload.push_back((uint8_t)fileName[i]);
	
	// convert string of encryptd file to bytes vector
	std::vector<char> enc_file(encFile.c_str(), encFile.c_str() + contentSize);

	for (size_t i = 0; i < contentSize; i++)//insert encrypted file content into payload
		filePayload.push_back((uint8_t)enc_file[i]);

	std::cout << "Size of file after decryption: " << " " << contentSize << std::endl;
	std::cout << "filePayload size = " << filePayload.size() << std::endl;

	return filePayload;
}


/* this function sends the data to server through the socket */
size_t Client::send_bytes(char* data, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(data, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent; //number of bytes to send
}


/* this function sends the data to server through the socket */
size_t Client::send_bytes(std::vector<char> vec, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(vec, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent; //number of bytes to send
}

/* this function sends the data to server through the socket */
size_t Client::send_bytes(std::string str, size_t amount)
{
	size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(str, amount));

	if (bytesSent < amount) {
		std::string err = "Sent fewer bytes than expected " + std::to_string(bytesSent) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesSent; //number of bytes to send
}

/*
* Attempt to receive an exact amount
*/
size_t Client::recive_bytes(size_t amount)
{
	
	clear_buffer(buffer_data, CHUNK_SIZE);

	size_t bytesRecv = boost::asio::read(socket_, boost::asio::buffer(buffer_data, amount));
	
	if (bytesRecv < amount) 
	{
		
		clear_buffer(buffer_data, CHUNK_SIZE);
		std::string err = "Received fewer bytes than expected " + std::to_string(bytesRecv) + " out of " + std::to_string(amount);
		throw std::exception(err.c_str());
	}
	return bytesRecv; //number of recived bytes
}


/*
* this function clears the buffer, in order to prevent recieving/sending old data 
*/
void Client::clear_buffer(char* buf, uint32_t size)
{
	for (uint32_t i = 0; i < size; ++i)
		buf[i] = 0;
}


/*
* this function unpack the header data
* the function gets bytes of the response header from server and save the unpacked header
* parameters to their appropriate fields in ResponseHeader structure
*/
void Client::parse_response_header(ResponseHeader* rh, char* arr)
{	
	rh->serverVersion = (uint8_t)arr[0];
	
	rh->statusCode = (uint8_t)arr[2] << 8 | (uint8_t)arr[1];

	rh->payloadSize = (uint8_t)(arr[6]) << 24 |
		(uint8_t)(arr[5]) << 16 |
		(uint8_t)(arr[4]) << 8 |
		(uint8_t)(arr[3]);
}

/*
* this function converts char to hexadecimal
*/
void Client::hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}


/*
* this function converts from hexadecimal to Ascii 
*/
std::string Client::hex2Ascii(const char* arr, size_t len)
{
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < len; i++)
		converter << std::setw(2) << (static_cast<unsigned>(arr[i]) & 0xFF);
	return converter.str();
}

/*
* this function converts Ascii data to hexadecimal
*/
void Client::ascii2HexBytes(char* dest, const std::string src, size_t len)
{
	std::string bytes = "";
	std::stringstream converter;
	converter << std::hex << std::setfill('0');

	for (size_t i = 0; i < (len * 2); i += 2)
	{
		converter << std::hex << src.substr(i, 2);
		int byte;
		converter >> byte;
		bytes += (byte & 0xFF);
		converter.str(std::string());
		converter.clear();
	}
	memcpy(dest, bytes.c_str(), len);
}

/*
* this function convert array to string
*/
std::string Client::convert_to_string(char* buffer)
{
	std::string str = "";
	for (size_t i = 0; i < 128; i++) {
		str += buffer[i];
	}
	return str;
}

/*
* this function create the connection to server
*/
void Client::connect_to_server()
{
	socket_.connect(tcp::endpoint(ip_, port_)); 
    std::cout << "client connected to server at port:  " << port_ << std::endl;
}



/*
* this function close the connection to server
*/
void Client::close_connection()
{
	socket_.close();

}


