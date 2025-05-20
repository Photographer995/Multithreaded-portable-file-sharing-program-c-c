#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <locale>
#include <mutex>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

std::atomic_bool g_exitThread(false);
SSL* g_ssl = nullptr;
std::mutex g_coutMutex;

void safePrint(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_coutMutex);
    std::cout << msg << std::flush;
}

int sslReadAll(SSL* ssl, void* buf, int count) {
    int total = 0;
    char* p = static_cast<char*>(buf);
    while (total < count) {
        int n = SSL_read(ssl, p + total, count - total);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

void saveFileFromSSL(const std::string& rawFilename) {
    // Удаляем '\n' и '\r' из имени файла
    std::string filename = rawFilename;
    filename.erase(std::remove(filename.begin(), filename.end(), '\n'), filename.end());  // :contentReference[oaicite:0]{index=0}
    filename.erase(std::remove(filename.begin(), filename.end(), '\r'), filename.end());

    // Читаем размер
    std::string sizeLine;
    char ch;
    while (SSL_read(g_ssl, &ch, 1) == 1) {
        if (ch == '\n') break;
        sizeLine.push_back(ch);
    }
    if (sizeLine.rfind("FILE_SIZE:", 0) != 0) {
        safePrint("Ошибка протокола: ожидалась метка FILE_SIZE\n");
        return;
    }
    uint64_t totalSize = std::stoull(sizeLine.substr(10));

    // Определяем offset (resume)
    uint64_t offset = 0;
    if (std::filesystem::exists(filename)) {
        offset = std::filesystem::file_size(filename);
        if (offset > totalSize) offset = 0;
    }

    std::ofstream outFile(filename, std::ios::binary | std::ios::app);
    if (!outFile) {
        safePrint("Не удалось открыть локальный файл для записи: " + filename + "\n");
        return;
    }

    uint64_t remaining = totalSize - offset;
    safePrint("Загружаем " + filename + ": уже " +
    std::to_string(offset) + " из " + std::to_string(totalSize) + " байт...\n");

    const size_t BUF_SIZE = 4096;
    char buffer[BUF_SIZE];
    while (remaining > 0) {
        int toRead = static_cast<int>(std::min<uint64_t>(BUF_SIZE, remaining));
        int n = sslReadAll(g_ssl, buffer, toRead);
        if (n <= 0) {
            safePrint("Ошибка чтения из SSL\n");
            break;
        }
        outFile.write(buffer, n);
        remaining -= n;
        uint64_t done = totalSize - remaining;
        int pct = static_cast<int>((done * 100) / totalSize);
        safePrint("\r[" + filename + "] " + std::to_string(pct) + "% (" +
        std::to_string(done) + "/" + std::to_string(totalSize) + ")");
    }

    outFile.close();
    safePrint("\nФайл " + filename + " загружен полностью.\n");
}

void recvThreadFunc() {
    std::string line;
    while (!g_exitThread.load()) {
        char ch;
        line.clear();
        while (SSL_read(g_ssl, &ch, 1) == 1) {
            if (ch == '\n') break;
            line.push_back(ch);
        }
        if (line.rfind("FILE_START:", 0) == 0) {
            saveFileFromSSL(line.substr(11));
        } else {
            safePrint(line + "\n");
        }
    }
}

int main(int argc, char* argv[]) {
    std::setlocale(LC_ALL, "");

    if (argc != 3) {
        std::cerr << "Использование: " << argv[0] << " <IP> <порт>\n";
        return 1;
    }
    std::string serverIP = argv[1];
    int port = std::atoi(argv[2]);

    #ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    #endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, serverIP.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    g_ssl = SSL_new(ctx);
    SSL_set_fd(g_ssl, sock);
    if (SSL_connect(g_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    safePrint("Connected to " + serverIP + ":" + std::to_string(port) + "\n");
    std::thread recvThr(recvThreadFunc);

    while (true) {
        safePrint("> ");
        std::string input; std::getline(std::cin, input);
        if (input.empty()) continue;

        std::istringstream iss(input);
        std::string cmd; iss >> cmd;

        if (cmd == "exit") {
            SSL_write(g_ssl, "exit\n", 5);
            break;
        }
        else if (cmd == "get") {
            std::string filename; iss >> filename;
            if (filename.empty()) {
                safePrint("Укажите имя файла\n");
                continue;
            }
            uint64_t offset = 0;
            if (std::filesystem::exists(filename))
                offset = std::filesystem::file_size(filename);

            std::ostringstream oss;
            oss << "get " << filename << " " << offset << "\n";
            std::string req = oss.str();
            SSL_write(g_ssl, req.c_str(), (int)req.size());
        }
        else {
            input += "\n";
            SSL_write(g_ssl, input.c_str(), (int)input.size());
        }
    }

    g_exitThread.store(true);
    SSL_shutdown(g_ssl);
    SSL_free(g_ssl);
    SSL_CTX_free(ctx);
    #ifdef _WIN32
    closesocket(sock); WSACleanup();
    #else
    close(sock);
    #endif

    recvThr.join();
    return 0;
}
