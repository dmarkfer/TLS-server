/*!
* @file TLSServer.h
* @brief mTLS (2wayAuth) server
* @author Domagoj Markota <domagoj.markota@gmail.com>
*/

#ifndef TLS_SERVER_H
#define TLS_SERVER_H


#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include <string>
#include <iostream>
#include <regex>
#include <exception>
#include <stdexcept>


/*!
* @class TLSServer
* @brief mTLS (2wayAuth) server
* @details TLS-server with REST methods and endpoints. Optional two way authentication.
*/
class TLSServer {
public:
    static const unsigned BUFFER_SIZE = 1024u; //!< Buffer size of SSL_read

    static bool listenFlag; //!< Server's listening state flag

private:
    const bool twoWayAuth; //!< Enabling two way authentication.
    const unsigned port; //!< Listening port
    const std::string pathServerCert; //!< Path to server's certificate
    const std::string pathServerPrivKey; //!< Path to server's private key
    const std::string pathClientCA; //!< Path to client's CA if \a twoWayAuth

    SSL_CTX * context; //!< Pointer to SSL context
    int sock; //!< Socket
    sockaddr_in listenerSin; //!< Client's data
    SSL * ssl; //!< Pointer to SSL
    std::string clientSubjectStr; //!< Subject from client's certificate if \a twoWayAuth
    std::string orgUnit; //!< Organizational unit from client's subject if \a twoWayAuth
    char * buffer; //!< Pointer to SSL_read buffer
    unsigned bufferLen; //!< Size of buffer for SSL_read


protected:
    /*!
    * Default constructor
    */
    TLSServer() = default;


public:
    /*!
    * Constructor
    * @param [in] twoWayAuth Enabling two way authentication.
    * @param [in] port Listening port
    * @param [in] pathServerCert Path to server's certificate
    * @param [in] pathServerPrivKey Path to server's private key
    * @param [in] pathClientCA Optional. Path to client's CA if \p twoWayAuth
    */
    TLSServer(
        const bool & twoWayAuth,
        const unsigned & port,
        const std::string & pathServerCert,
        const std::string & pathServerPrivKey,
        const std::string & pathClientCA = ""
    );


    /*!
    * Default virtual destructor
    */
    virtual ~TLSServer();


    /*!
    * Initializes server's \a context and \a sock.
    */
    virtual void init();


    /*!
    * Server starts listening.
    */
    virtual void run();


protected:
    /*!
    * Prepares \a context
    */
    virtual void setupContext();


    /*!
    * Prepares \a sock
    */
    virtual void setupSocket();


    /*!
    * Extracts subject \a clientSubjectStr from client's certificate if \a twoWayAuth.
    */
    virtual void retrieveSubjectFromClient();


    /*!
    * Extracts organizational unit \a orgUnit from \a clientSubjectStr.
    */
    virtual void extractOAfromSubjectStr();


    /*!
    * Extracts REST method and endpoints from client's request.
    */
    virtual void parseMethodAndEndpoint();


    /*!
    * RESTful switch
    * @param [in] method REST method
    * @param [in] endpoint REST endpoint
    */
    virtual void restCall(const std::string & method, const std::string & endpoint);


    /*!
    * Extracts JSON from client's request.
    * @param [in,out] jsonFoundFlag Signalizing JSON is reached
    * @param [in,out] jsonColonFoundFlag Signalizing colon within JSON is reached
    * @param [in,out] jsonEndFlag Signalizing end of JSON
    * @param [in,out] formatStr Collected data from JSON
    */
    virtual void lookForJSON(
        bool & jsonFoundFlag,
        bool & jsonColonFoundFlag,
        bool & jsonEndFlag,
        std::string & formatStr
    );


    /*!
    * Parse JSON data and SSL_write respond
    * @param [in] formatStr Data suggesting format of response
    */
    virtual void parseJSONandRespond(std::string & formatStr);


public:
    const bool & isTwoWayAuth() const;
    const auto & getPort() const;
    const auto & getPathServerCert() const;
    const auto & getPathServerPrivKey() const;
    const auto & getPathClientCA() const;

};


#endif // TLS_SERVER_H
