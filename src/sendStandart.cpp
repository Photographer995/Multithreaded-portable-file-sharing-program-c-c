#include "sendStandart.h"
#include <iostream>
#include <filesystem>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#endif

std::string removelastElement(const std::string &path) {
    if(path.empty()) return path;
    std::string trimmed = path;
    if(trimmed.back() == '/' || trimmed.back() == '\\')
        trimmed.pop_back();
    size_t pos = trimmed.find_last_of("/\\");
    if (pos == std::string::npos) return trimmed;
    return trimmed.substr(0, pos);
}

bool parseArguments(int argc, char* argv[], int &port, std::string &rootDir) {
    if(argc != 3) {
        std::cerr << "Использование: " << argv[0] << " <порт> <путь_к_корневому_каталогу>" << std::endl;
        return false;
    }
    try {
        port = std::stoi(argv[1]);
    } catch(...) {
        std::cerr << "Неверный номер порта" << std::endl;
        return false;
    }
    if(port < 0 || port > 65535) {
        std::cerr << "Порт должен быть в диапазоне 0-65535" << std::endl;
        return false;
    }
    rootDir = argv[2];
    if(!std::filesystem::is_directory(rootDir)) {
        std::cerr << "Указанный путь не является директорией" << std::endl;
        return false;
    }
    return true;
}

std::string getLocalIpAddress() {
    #ifdef _WIN32
    char hostname[256];
    if(gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
        return "127.0.0.1";
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0)
        return "127.0.0.1";
    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    std::string ip = inet_ntoa(addr->sin_addr);
    freeaddrinfo(res);
    return ip;
    #else
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    if (getifaddrs(&ifaddr) == -1) {
        return ip;
    }
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            if (strcmp(ifa->ifa_name, "lo") != 0) {
                inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return std::string(ip);
    #endif
}
