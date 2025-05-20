#ifndef SENDSTANDART_H
#define SENDSTANDART_H

#include <string>
#include <filesystem>
#include <openssl/ssl.h>

std::string removelastElement(const std::string &path);
bool parseArguments(int argc, char* argv[], int &port, std::string &rootDir);
std::string getLocalIpAddress();

#endif // SENDSTANDART_H
