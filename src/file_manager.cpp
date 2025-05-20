#include "file_manager.h"
#include <cstring>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <regex>
#include <openssl/ssl.h>
#include <mutex>

// Вспомогательная функция для отправки через TLS
static int secure_send(SSL* ssl, const char* buf, int len) {
    return SSL_write(ssl, buf, len);
}

FileManager::FileManager(const std::string &rootPath) : rootPath(rootPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    currentPath = std::filesystem::canonical(rootPath).string();
}

std::string FileManager::getCurrentPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return currentPath;
}

bool FileManager::setCurrentPath(const std::string &newPath) {
    try {
        std::filesystem::path p(newPath);
        std::filesystem::path canonicalNew = std::filesystem::canonical(p);
        std::filesystem::path canonicalRoot = std::filesystem::canonical(rootPath);
        if(canonicalNew.string().find(canonicalRoot.string()) != 0)
            return false;
        if(std::filesystem::is_directory(canonicalNew)) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                currentPath = canonicalNew.string();
            }
            return true;
        } else {
            return false;
        }
    } catch(...) {
        return false;
    }
}

std::string FileManager::removeLastElement(const std::string &path) const {
    if(path.empty()) return path;
    std::string trimmed = path;
    if(trimmed.back() == '/' || trimmed.back() == '\\')
        trimmed.pop_back();
    size_t pos = trimmed.find_last_of("/\\");
    if(pos == std::string::npos)
        return trimmed;
    return trimmed.substr(0, pos);
}

void FileManager::sendDirectoryListing(SSL* ssl) const {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        path = currentPath;
    }
    std::stringstream ss;
    ss << "Текущий каталог: " << path << "\n";
    for(const auto &entry: std::filesystem::directory_iterator(path)) {
        std::string name = entry.path().filename().string();
        if(entry.is_directory())
            name += "/";
        ss << name << "\n";
    }
    std::string listStr = ss.str();
    secure_send(ssl, listStr.c_str(), listStr.size());
}

void FileManager::sendFileToClient(SSL* ssl, const std::string &filename, std::streampos offset) const {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        path = currentPath;
    }
    std::string filepath = path + "/" + filename;
    if(!std::filesystem::exists(filepath)) {
        std::string err = "Ошибка: файл не найден\n";
        secure_send(ssl, err.c_str(), err.size());
        return;
    }

    std::ifstream file(filepath, std::ios::binary);
    if(!file) {
        std::string err = "Ошибка: не удалось открыть файл\n";
        secure_send(ssl, err.c_str(), err.size());
        return;
    }

    file.seekg(0, std::ios::end);
    std::streampos filesize = file.tellg();
    if(offset > filesize) {
        std::string err = "Ошибка: неверный offset\n";
        secure_send(ssl, err.c_str(), err.size());
        return;
    }
    std::streamoff remaining = filesize - offset;
    std::string header = "FILE " + std::to_string(remaining) + "\n";
    secure_send(ssl, header.c_str(), header.size());
    file.seekg(offset, std::ios::beg);
    const size_t bufferSize = 1024;
    char buffer[bufferSize];
    while(file && remaining > 0) {
        file.read(buffer, bufferSize);
        std::streamsize bytesRead = file.gcount();
        if(bytesRead <= 0)
            break;
        secure_send(ssl, buffer, bytesRead);
        remaining -= bytesRead;
    }
    file.close();
}

void FileManager::receiveFile(SSL* ssl, const std::string &filename, std::streampos offset) const {
    std::streampos resumeOffset = offset;
    // Для защиты ввода-вывода в многопоточном режиме используем статический мьютекс
    static std::mutex io_mutex;
    if(offset == 0 && std::filesystem::exists(filename)) {
        {
            std::lock_guard<std::mutex> io_lock(io_mutex);
            std::cout << "Файл " << filename << " уже существует. Возобновить передачу? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            if(answer == "y" || answer == "Y") {
                resumeOffset = std::filesystem::file_size(filename);
            } else {
                resumeOffset = 0;
            }
        }
    }
    std::string command = "get " + filename + " " + std::to_string(static_cast<long long>(resumeOffset)) + "\n";
    secure_send(ssl, command.c_str(), command.size());
    char header[128];
    memset(header, 0, sizeof(header));
    int bytes = SSL_read(ssl, header, sizeof(header)-1);
    if(bytes <= 0) {
        {
            std::lock_guard<std::mutex> io_lock(io_mutex);
            std::cout << "Ошибка получения заголовка файла" << std::endl;
        }
        return;
    }
    std::string headerStr(header);
    if(headerStr.find("FILE ") != 0) {
        std::lock_guard<std::mutex> io_lock(io_mutex);
        std::cout << headerStr;
        return;
    }
    std::istringstream iss(headerStr);
    std::string fileTag;
    size_t fileSize;
    iss >> fileTag >> fileSize;
    std::ofstream file;
    if(resumeOffset > 0)
        file.open(filename, std::ios::binary | std::ios::app);
    else
        file.open(filename, std::ios::binary);
    if(!file) {
        {
            std::lock_guard<std::mutex> io_lock(io_mutex);
            std::cout << "Не удалось открыть файл для записи" << std::endl;
        }
        return;
    }
    const size_t bufferSize = 1024;
    char bufferData[bufferSize];
    size_t remaining = fileSize;
    while(remaining > 0) {
        int chunk = SSL_read(ssl, bufferData, std::min((size_t)bufferSize, remaining));
        if(chunk <= 0)
            break;
        file.write(bufferData, chunk);
        remaining -= chunk;
    }
    file.close();
    {
        std::lock_guard<std::mutex> io_lock(io_mutex);
        std::cout << "\nПередача файла завершена." << std::endl;
    }
}

void FileManager::sendFileInfo(SSL* ssl, const std::string &filename) const {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        path = currentPath;
    }
    std::string filepath = path + "/" + filename;
    std::stringstream ss;
    if(!std::filesystem::exists(filepath)) {
        ss << "Ошибка: файл или каталог не найден\n";
    } else {
        ss << "Информация о " << filename << ":\n";
        auto status = std::filesystem::status(filepath);
        auto ftype = status.type();
        switch (ftype) {
            case std::filesystem::file_type::regular:
                ss << "Тип: обычный файл\n";
                break;
            case std::filesystem::file_type::directory:
                ss << "Тип: каталог\n";
                break;
            case std::filesystem::file_type::symlink:
                ss << "Тип: символическая ссылка\n";
                break;
            case std::filesystem::file_type::block:
                ss << "Тип: блочное устройство\n";
                break;
            case std::filesystem::file_type::character:
                ss << "Тип: символьное устройство\n";
                break;
            case std::filesystem::file_type::fifo:
                ss << "Тип: FIFO (канал)\n";
                break;
            case std::filesystem::file_type::socket:
                ss << "Тип: сокет\n";
                break;
            default:
                ss << "Тип: неизвестный\n";
                break;
        }
        if(ftype == std::filesystem::file_type::regular) {
            try {
                uintmax_t size = std::filesystem::file_size(filepath);
                ss << "Размер: " << size << " байт\n";
            } catch(...) {
                ss << "Размер: неизвестен\n";
            }
        }
        auto perms = status.permissions();
        std::string permissionStr;
        permissionStr.push_back((perms & std::filesystem::perms::owner_read)  != std::filesystem::perms::none ? 'r' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::owner_write) != std::filesystem::perms::none ? 'w' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::owner_exec)  != std::filesystem::perms::none ? 'x' : '-');
        permissionStr.push_back(' ');
        permissionStr.push_back((perms & std::filesystem::perms::group_read)  != std::filesystem::perms::none ? 'r' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::group_write) != std::filesystem::perms::none ? 'w' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::group_exec)  != std::filesystem::perms::none ? 'x' : '-');
        permissionStr.push_back(' ');
        permissionStr.push_back((perms & std::filesystem::perms::others_read)  != std::filesystem::perms::none ? 'r' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::others_write) != std::filesystem::perms::none ? 'w' : '-');
        permissionStr.push_back((perms & std::filesystem::perms::others_exec)  != std::filesystem::perms::none ? 'x' : '-');
        ss << "Права доступа: " << permissionStr << "\n";
        try {
            auto ftime = std::filesystem::last_write_time(filepath);
            auto sctp = std::chrono::system_clock::to_time_t(
                std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - decltype(ftime)::clock::now() + std::chrono::system_clock::now()
                )
            );
            ss << "Последнее изменение: " << std::ctime(&sctp);
        } catch(...) {
            ss << "Не удалось получить время последнего изменения\n";
        }
    }
    std::string infoStr = ss.str();
    secure_send(ssl, infoStr.c_str(), infoStr.size());
}

static std::string globToRegex(const std::string &glob) {
    std::string regex;
    regex.push_back('^');
    for (char c : glob) {
        switch (c) {
            case '*':
                regex.append(".*");
                break;
            case '?':
                regex.push_back('.');
                break;
            case '.':
                regex.append("\\.");
                break;
            default:
                if(std::isalnum(c)) {
                    regex.push_back(c);
                } else {
                    regex.push_back('\\');
                    regex.push_back(c);
                }
                break;
        }
    }
    regex.push_back('$');
    return regex;
}

void FileManager::findFiles(SSL* ssl, SearchCategory category, const std::string &pattern) const {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        path = currentPath;
    }
    std::stringstream ss;
    std::regex re(globToRegex(pattern), std::regex::icase);
    bool found = false;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path)) {
        if (category == SearchCategory::Files && !entry.is_regular_file())
            continue;
        if (category == SearchCategory::Directories && !entry.is_directory())
            continue;
        std::string name = entry.path().filename().string();
        if (std::regex_match(name, re)) {
            found = true;
            ss << entry.path().string() << "\n";
        }
    }
    if (!found) {
        ss << "Ничего не найдено по шаблону \"" << pattern << "\"\n";
    }
    std::string result = ss.str();
    secure_send(ssl, result.c_str(), result.size());
}
