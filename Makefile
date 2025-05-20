# Переменные
CXX       := g++
CXXFLAGS  := -Wall -std=c++17 -Iinclude -pthread -lssl -lcrypto
SRC_DIR   := src
OBJ_DIR   := obj
BIN_DIR   := bin

# Исходники (отредактируйте имена файлов под ваш проект)
SRCS_SERVER := $(SRC_DIR)/tls_server.cpp $(SRC_DIR)/file_manager.cpp $(SRC_DIR)/sendStandart.cpp
SRCS_CLIENT := $(SRC_DIR)/tls_client.cpp $(SRC_DIR)/file_manager.cpp $(SRC_DIR)/sendStandart.cpp

# Объектные файлы
OBJS_SERVER := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS_SERVER))
OBJS_CLIENT := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS_CLIENT))

# Цели по умолчанию
all: $(BIN_DIR)/server $(BIN_DIR)/client

# Правило для сборки сервера
$(BIN_DIR)/server: $(OBJS_SERVER)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Правило для сборки клиента
$(BIN_DIR)/client: $(OBJS_CLIENT)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Общее правило для объектных файлов
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Правило очистки
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
