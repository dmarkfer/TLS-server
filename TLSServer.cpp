#include "TLSServer.h"



bool TLSServer::listenFlag = true;



TLSServer::TLSServer(
    const bool & twoWayAuth,
    const unsigned & port,
    const std::string & pathServerCert,
    const std::string & pathServerPrivKey,
    const std::string & pathClientCA
):
    twoWayAuth(twoWayAuth),
    port(port),
    pathServerCert(pathServerCert),
    pathServerPrivKey(pathServerPrivKey),
    pathClientCA(pathClientCA),

    context(nullptr),
    ssl(nullptr),
    buffer(nullptr)
{
    this->buffer = new char[TLSServer::BUFFER_SIZE];
}



TLSServer::~TLSServer() {
    delete[] this->buffer;
}



void TLSServer::init() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    try {
        this->setupContext();
    }
    catch(const std::exception & e) {
        std::cerr << e.what() << std::endl;
    }

    try {
        this->setupSocket();
    }
    catch(const std::exception & e) {
        SSL_CTX_free(this->context);
        std::cerr << e.what() << std::endl;
    }
}



void TLSServer::run() {
    while(TLSServer::listenFlag) {
        socklen_t listenerSinLen = sizeof(listenerSin);

        int netFileDescp = accept(
            this->sock,
            (sockaddr *)&this->listenerSin,
            &listenerSinLen
        );
        if(netFileDescp < 0) {
            std::cerr << "Failed to accept connection\n";
            continue;
        }

        if(! (this->ssl = SSL_new(this->context))) {
            close(netFileDescp);
            std::cerr << "Couldn't get SSL handle from the context\n";
            continue;
        }

        SSL_set_fd(this->ssl, netFileDescp);

        int tlsHandshake = SSL_accept(this->ssl);
        if(tlsHandshake != 1) {
            std::cerr << "Couldn't perform SSL handshake\n";

            if(tlsHandshake != 0) {
                SSL_shutdown(this->ssl);
            }

            SSL_free(this->ssl);
            close(netFileDescp);
            continue;
        }

        std::cerr << "Successful handshake with "
                  << inet_ntoa(listenerSin.sin_addr)
                  << ":"
                  << ntohs(listenerSin.sin_port)
                  << std::endl;


        if(this->twoWayAuth) {
            try {
                this->retrieveSubjectFromClient();
            }
            catch(const std::exception & e) {
                std::cerr << e.what() << std::endl;
            }

            try {
                this->extractOAfromSubjectStr();
            }
            catch(const std::exception & e) {
                std::cerr << e.what() << std::endl;
            }
        }

        
        try {
            this->parseMethodAndEndpoint();
        }
        catch(const std::exception & e) {
            std::cerr << e.what() << std::endl;
        }


        SSL_shutdown(this->ssl);
        SSL_free(this->ssl);
        close(netFileDescp);
    }

    close(this->sock);
}



void TLSServer::setupContext() {
    if(! (this->context = SSL_CTX_new(TLS_server_method()))) {
        throw std::runtime_error("SSL_CTX_new failed\n");
    }


    if(this->twoWayAuth) {
        if(SSL_CTX_load_verify_locations(this->context, this->pathClientCA.c_str(), nullptr) != 1) {
            SSL_CTX_free(this->context);
            throw std::runtime_error("Setting CA failed\n");
        }

        SSL_CTX_set_client_CA_list(this->context, SSL_load_client_CA_file(this->pathClientCA.c_str()));
    }


    if(SSL_CTX_use_certificate_file(this->context, this->pathServerCert.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(this->context);
        throw std::runtime_error("Setting server's certificate failed\n");
    }

    if(SSL_CTX_use_PrivateKey_file(this->context, this->pathServerPrivKey.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(this->context);
        throw std::runtime_error("Setting server's key failed\n");
    }
    if(SSL_CTX_check_private_key(this->context) != 1) {
        SSL_CTX_free(this->context);
        throw std::runtime_error("Matching server's certificate and the key failed\n");
    }

    SSL_CTX_set_mode(this->context, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(
        this->context,
        this->twoWayAuth ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE,
        nullptr
    );
    SSL_CTX_set_verify_depth(this->context, 1);
}



void TLSServer::setupSocket() {
    if((this->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        throw std::runtime_error("Socket creation failed\n");
    }

    void * tempPtr;
    if(setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, &tempPtr, sizeof(tempPtr)) < 0) {
        close(this->sock);
        throw std::runtime_error("Setting SO_REUSEADDR on the socket failed\n");
    }

    sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(this->port);

    if(bind(this->sock, (sockaddr *)&sin, sizeof(sin)) < 0) {
        close(this->sock);
        throw std::runtime_error("Socket bind failed\n");
    }

    if(listen(this->sock, SOMAXCONN) < 0) {
        close(this->sock);
        throw std::runtime_error("Socket: listen failed\n");
    }
}



void TLSServer::retrieveSubjectFromClient() {
    X509 * cert = SSL_get_peer_certificate(this->ssl);
    X509_NAME * subject = X509_get_subject_name(cert);
    char * subjectCstr = new char[TLSServer::BUFFER_SIZE + 1];
    X509_NAME_oneline(subject, subjectCstr, TLSServer::BUFFER_SIZE);
    this->clientSubjectStr = subjectCstr;
    delete[] subjectCstr;
    X509_free(cert);
}



void TLSServer::extractOAfromSubjectStr() {
    std::regex re("/OU=[^/]*/");
    std::regex_iterator<std::string::iterator> rit(
        this->clientSubjectStr.begin(),
        this->clientSubjectStr.end(),
        re
    );
    this->orgUnit = rit->str().substr(4, rit->str().size() - 5);
}



void TLSServer::lookForJSON(
    bool & jsonFoundFlag,
    bool & jsonColonFoundFlag,
    bool & jsonEndFlag,
    std::string & formatStr
) {
    for(unsigned bufferPos = 0u; bufferPos < this->bufferLen  &&  !jsonEndFlag; ++bufferPos) {
        if(jsonFoundFlag) {
            if(jsonColonFoundFlag) {
                if(this->buffer[bufferPos] == '}') {
                    jsonEndFlag = true;
                } else {
                    formatStr += this->buffer[bufferPos];
                }
            } else if(this->buffer[bufferPos] == ':') {
                jsonColonFoundFlag = true;
            }
        } else if(this->buffer[bufferPos] == '{') {
            jsonFoundFlag = true;
        }
    }
}



void TLSServer::parseJSONandRespond(std::string & formatStr) {
    //
}



void TLSServer::parseMethodAndEndpoint() {
    this->bufferLen = SSL_read(this->ssl, this->buffer, TLSServer::BUFFER_SIZE);
    if(this->bufferLen < 0) {
        throw std::runtime_error("SSL_read failed\n");
    }

    std::string bufferStr = std::string(this->buffer, this->bufferLen);
    const auto firstBlankPos = bufferStr.find(" ");
    std::string method(bufferStr.substr(0, firstBlankPos));
    std::string endpoint(bufferStr.substr(firstBlankPos + 1, bufferStr.find(" ", firstBlankPos + 1) - firstBlankPos - 1));

    this->restCall(method, endpoint);
}



void TLSServer::restCall(const std::string & method, const std::string & endpoint) {
    //
}



const bool & TLSServer::isTwoWayAuth() const {
    return this->twoWayAuth;
}



const auto & TLSServer::getPort() const {
    return this->port;
}



const auto & TLSServer::getPathServerCert() const {
    return this->pathServerCert;
}



const auto & TLSServer::getPathServerPrivKey() const {
    return this->pathServerPrivKey;
}



const auto & TLSServer::getPathClientCA() const {
    return this->pathClientCA;
}
