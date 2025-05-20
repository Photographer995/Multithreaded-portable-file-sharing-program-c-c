#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <thread>
#include <mutex>
#include "file_manager.h"
#include <openssl/ssl.h>
#include <openssl/err.h>


#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#endif

// Глобальные переменные для логирования
std::mutex g_logMutex;
std::ofstream g_logFile;

// Функция возвращающая строку с текущим временем
std::string getCurrentTimeStr() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::string timeStr = std::ctime(&now_time);
    timeStr.erase(std::remove(timeStr.begin(), timeStr.end(), '\n'), timeStr.end());
    return timeStr;
}

// Функция для потокобезопасного логирования в файл
void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile.is_open()) {
        g_logFile << "[" << getCurrentTimeStr() << "] " << message << std::endl;
        g_logFile.flush();
    }
    // Дополнительно можно выводить сообщение и в консоль:
    std::cout << "[" << getCurrentTimeStr() << "] " << message << std::endl;
}

struct ClientInfo {
    SSL* ssl;
    int clientSocket;
    std::string ip;
};

std::string pathToRootdir;
FileManager* globalFileManager = nullptr;
void sendFileToClient(SSL* ssl, const std::string& filename, std::streampos offset = 0) {
    // Путь к файлу
    std::filesystem::path filepath = globalFileManager->getCurrentPath();
    filepath /= filename;

    if (!std::filesystem::exists(filepath) || !std::filesystem::is_regular_file(filepath)) {
        std::string msg = "Ошибка: файл не существует\n";
        SSL_write(ssl, msg.c_str(), msg.size());
        logMessage("Попытка отправить несуществующий файл: " + filename);
        return;
    }

    // Открываем файл в бинарном режиме и сразу узнаём размер
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::string msg = "Ошибка: не удалось открыть файл\n";
        SSL_write(ssl, msg.c_str(), msg.size());
        logMessage("Не удалось открыть файл " + filename);
        return;
    }
    uint64_t filesize = static_cast<uint64_t>(file.tellg());
    file.seekg(offset);

    // 1) Отправляем метку начала
    std::string startHdr = "FILE_START:" + filename + "\n";
    SSL_write(ssl, startHdr.c_str(), startHdr.size());
    logMessage("Начата передача файла " + filename + " с offset " + std::to_string(offset));

    // 2) Отправляем метку размера
    std::string sizeHdr = "FILE_SIZE:" + std::to_string(filesize) + "\n";
    SSL_write(ssl, sizeHdr.c_str(), sizeHdr.size());

    // 3) Отправляем сами данные, начиная с offset
    const size_t BUF_SZ = 4096;
    char buffer[BUF_SZ];
    uint64_t remaining = filesize - offset;
    while (remaining > 0) {
        size_t chunk = static_cast<size_t>(std::min<uint64_t>(BUF_SZ, remaining));
        file.read(buffer, chunk);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead <= 0) break;
        SSL_write(ssl, buffer, static_cast<int>(bytesRead));
        remaining -= static_cast<uint64_t>(bytesRead);
    }

    file.close();
    logMessage("Передача файла " + filename + " завершена.");
}

void findAndSendResults(SSL* ssl, const std::string& pattern, bool onlyFiles, bool onlyDirs) {
    std::filesystem::path currentPath = globalFileManager->getCurrentPath();
    std::ostringstream result;

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(currentPath)) {
            const std::string name = entry.path().filename().string();
            if (name.find(pattern) != std::string::npos) {
                if (onlyFiles && !entry.is_regular_file()) continue;
                if (onlyDirs && !entry.is_directory()) continue;

                std::string type = entry.is_directory() ? "[DIR] " : "[FILE]";
                std::string relPath = std::filesystem::relative(entry.path(), currentPath).string();
                result << type << " " << relPath << "\n";
            }
        }

        std::string resultStr = result.str();
        if (resultStr.empty()) {
            resultStr = "Ничего не найдено.\n";
        }
        SSL_write(ssl, resultStr.c_str(), resultStr.size());
        logMessage("Результаты поиска отправлены клиенту.");
    } catch (const std::exception& e) {
        std::string err = "Ошибка при выполнении поиска: ";
        err += e.what();
        SSL_write(ssl, err.c_str(), err.size());
        logMessage("Ошибка при поиске: " + std::string(e.what()));
    }
}

void* handle_client(void* arg) {
    ClientInfo* info = static_cast<ClientInfo*>(arg);
    SSL* ssl = info->ssl;
    int clientSocket = info->clientSocket;
    std::string clientIp = info->ip;
    delete info;

    logMessage("Клиент " + clientIp + " подключился.");
    std::string welcome = "Добро пожаловать на сервер обмена файлами!\n";
    SSL_write(ssl, welcome.c_str(), welcome.size());

    globalFileManager->sendDirectoryListing(ssl);

    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytesReceived <= 0)
            break;

        std::string command(buffer);
        command.erase(std::remove(command.begin(), command.end(), '\n'), command.end());
        command.erase(std::remove(command.begin(), command.end(), '\r'), command.end());

        logMessage("Клиент " + clientIp + " отправил команду: " + command);

        if (command == "exit") {
            std::string bye = "Соединение закрывается...\n";
            SSL_write(ssl, bye.c_str(), bye.size());
            logMessage("Клиент " + clientIp + " завершил соединение.");
            break;
        } else if (command == "ls") {
            globalFileManager->sendDirectoryListing(ssl);
        } else if (command.substr(0, 3) == "cd ") {
            std::string dir = command.substr(3);
            std::string newPath = globalFileManager->getCurrentPath() + "/" + dir;

            try {
                std::filesystem::path p(newPath);
                std::filesystem::path canonicalNew = std::filesystem::canonical(p);
                std::filesystem::path canonicalRoot = std::filesystem::canonical(pathToRootdir);

                if (canonicalNew.string().find(canonicalRoot.string()) != 0) {
                    std::string err = "Ошибка: доступ запрещён\n";
                    SSL_write(ssl, err.c_str(), err.size());
                    logMessage("Попытка доступа к каталогу вне корневой директории: " + newPath);
                } else if (std::filesystem::is_directory(canonicalNew)) {
                    if (globalFileManager->setCurrentPath(canonicalNew.string())) {
                        std::string ok = "Текущий каталог изменён: " + globalFileManager->getCurrentPath() + "\n";
                        SSL_write(ssl, ok.c_str(), ok.size());
                        logMessage("Клиент " + clientIp + " сменил каталог на: " + globalFileManager->getCurrentPath());
                    } else {
                        std::string err = "Ошибка: не удалось сменить каталог\n";
                        SSL_write(ssl, err.c_str(), err.size());
                        logMessage("Ошибка смены каталога для клиента " + clientIp + ": " + canonicalNew.string());
                    }
                } else {
                    std::string err = "Ошибка: не является директорией\n";
                    SSL_write(ssl, err.c_str(), err.size());
                    logMessage("Пользователь " + clientIp + " пытался перейти не в каталог: " + canonicalNew.string());
                }
            } catch (...) {
                std::string err = "Ошибка: неверный путь\n";
                SSL_write(ssl, err.c_str(), err.size());
                logMessage("Клиент " + clientIp + " ввёл неверный путь: " + newPath);
            }
        } else if (command.substr(0, 4) == "get ") {
            std::istringstream iss(command);
            std::string cmd, filename;
            long long offset_val = 0;
            iss >> cmd >> filename;
            if (iss >> offset_val) {
                // offset передан
            }
            logMessage("Клиент " + clientIp + " запросил получение файла: " + filename + " с offset " + std::to_string(offset_val));
            sendFileToClient(ssl, filename, static_cast<std::streampos>(offset_val));
        } else if (command.substr(0, 5) == "stat ") {
            std::istringstream iss(command);
            std::string cmd, filename;
            iss >> cmd >> filename;
            logMessage("Клиент " + clientIp + " запросил информацию о файле: " + filename);
            globalFileManager->sendFileInfo(ssl, filename);
        } else if (command.substr(0, 4) == "find") {
            std::istringstream iss(command);
            std::string cmd, flag, pattern;
            iss >> cmd >> flag >> pattern;

            bool onlyFiles = false;
            bool onlyDirs = false;

            if (flag == "-f") {
                onlyFiles = true;
            } else if (flag == "-d") {
                onlyDirs = true;
            } else {
                // Возможно, паттерн указан без флага
                pattern = flag;
            }

            logMessage("Клиент " + clientIp + " ищет: \"" + pattern + "\""
            + (onlyFiles ? " (только файлы)" : onlyDirs ? " (только директории)" : ""));
            findAndSendResults(ssl, pattern, onlyFiles, onlyDirs);
        }
        else if (command == "help") {
            std::string helpText =
            "Доступные команды:\n"
            "ls               - показать список файлов и каталогов\n"
            "cd <dir>         - сменить текущий каталог\n"
            "get <file> [off] - загрузить файл с сервера (опционально с offset)\n"
            "find [-f|-d] <pattern> - поиск файлов/каталогов по шаблону\n"
            "stat <file>      - показать информацию о файле/каталоге\n"
            "exit             - закрыть соединение\n";
            SSL_write(ssl, helpText.c_str(), helpText.size());
        } else {
            std::string unknown = "Неизвестная команда\n";
            SSL_write(ssl, unknown.c_str(), unknown.size());
            logMessage("Клиент " + clientIp + " отправил неизвестную команду: " + command);
        }
    }

    logMessage("Клиент " + clientIp + " отключился.");

    #ifdef _WIN32
    closesocket(clientSocket);
    #else
    close(clientSocket);
    #endif

    SSL_shutdown(ssl);
    SSL_free(ssl);
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Использование: " << argv[0] << " <порт> <директория>" << std::endl;
        return -1;
    }

    int port = std::atoi(argv[1]);
    pathToRootdir = argv[2];

    FileManager fileManager(pathToRootdir);
    globalFileManager = &fileManager;

    // Инициализация лог-файла
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logFile.open("server.log", std::ios::out | std::ios::app);
        if (!g_logFile.is_open()) {
            std::cerr << "Не удалось открыть лог-файл" << std::endl;
            return -1;
        }
    }
    logMessage("Сервер запускается. Корневая директория: " + pathToRootdir);

    #ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        logMessage("Ошибка инициализации Winsock");
        std::cerr << "Ошибка инициализации Winsock\n";
        return -1;
    }
    #endif

    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        logMessage("Ошибка создания SSL_CTX");
        std::cerr << "Ошибка создания SSL_CTX\n";
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        logMessage("Ошибка загрузки сертификата/ключа");
    std::cerr << "Ошибка загрузки сертификата/ключа\n";
    ERR_print_errors_fp(stderr);
    return -1;
        }

        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) {
            logMessage("Не удалось создать сокет");
            std::cerr << "Не удалось создать сокет\n";
            return -1;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            logMessage("Ошибка привязки сокета к порту");
            std::cerr << "Ошибка привязки сокета\n";
            return -1;
        }

        listen(serverSocket, 5);
        logMessage("Сервер запущен на порту " + std::to_string(port));

        while (true) {
            sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            if (clientSocket < 0) {
                logMessage("Ошибка accept при подключении клиента");
                std::cerr << "Ошибка accept\n";
                continue;
            }

            std::string clientIp = inet_ntoa(clientAddr.sin_addr);
            logMessage("Новое подключение от: " + clientIp);

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, clientSocket);
            if (SSL_accept(ssl) <= 0) {
                logMessage("Ошибка TLS-соединения с клиентом " + clientIp);
                std::cerr << "Ошибка TLS-соединения\n";
                ERR_print_errors_fp(stderr);
                #ifdef _WIN32
                closesocket(clientSocket);
                #else
                close(clientSocket);
                #endif
                SSL_free(ssl);
                continue;
            }

            ClientInfo* pClient = new ClientInfo{ ssl, clientSocket, clientIp };
            pthread_t threadId;
            if (pthread_create(&threadId, nullptr, handle_client, pClient) != 0) {
                logMessage("Не удалось создать поток для клиента " + clientIp);
                std::cerr << "Не удалось создать поток клиента\n";
                #ifdef _WIN32
                closesocket(clientSocket);
                #else
                close(clientSocket);
                #endif
                SSL_free(ssl);
                delete pClient;
            } else {
                pthread_detach(threadId);
            }
        }

        close(serverSocket);
        SSL_CTX_free(ctx);
        logMessage("Сервер остановлен.");
        return 0;
}
