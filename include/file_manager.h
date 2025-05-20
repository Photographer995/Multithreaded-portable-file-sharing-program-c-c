#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <string>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <regex>
#include <cctype>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <openssl/ssl.h>

class FileManager {
public:
    enum class SearchCategory {
        All,
        Files,
        Directories
    };

    FileManager(const std::string &rootPath);
    std::string getCurrentPath() const;
    bool setCurrentPath(const std::string &newPath);
    std::string removeLastElement(const std::string &path) const;
    void sendDirectoryListing(SSL* ssl) const;
    void sendFileToClient(SSL* ssl, const std::string &filename, std::streampos offset) const;
    void receiveFile(SSL* ssl, const std::string &filename, std::streampos offset) const;
    void sendFileInfo(SSL* ssl, const std::string &filename) const;
    void findFiles(SSL* ssl, SearchCategory category, const std::string &pattern) const;

private:
    std::string rootPath;
    std::string currentPath;
    mutable std::mutex m_mutex; // мьютекс для защиты общих данных
};

#endif // FILE_MANAGER_H
