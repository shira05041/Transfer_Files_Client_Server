#include "Client.h"

int main(int argc, char* argv[])
{
    try
    {
        boost::asio::io_context io_context;
        Client c(io_context);

        c.prosess_requsts();

        c.close_connection();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}