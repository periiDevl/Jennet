# -----------------------------
# Makefile for Jennet Project
# -----------------------------

# Use the system's default g++
CXX := g++
CXXFLAGS := -std=c++20 -O2 -fPIC -Wall -Wextra

# Paths and libraries
PCAPPP_DIR := /home/jon/Documents/Projects/Jennet
INCLUDES := -I. -I$(PCAPPP_DIR)/include/pcapplusplus -I./JNET $(shell pkg-config --cflags Qt5Widgets)
LIBS := $(PCAPPP_DIR)/lib/libPcap++.a \
        $(PCAPPP_DIR)/lib/libPacket++.a \
        $(PCAPPP_DIR)/lib/libCommon++.a \
        -lpcap -lcjson $(shell pkg-config --libs Qt5Widgets) \
        -static-libstdc++ -static-libgcc

# Sources
SRC := $(wildcard *.cpp)
OBJ := $(SRC:.cpp=.o)
TARGET := jnet

# -----------------------------
# Rules
# -----------------------------

all: check_deps $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(INCLUDES) $(LIBS)
	@echo "[+] Compilation successful."

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
	@echo "[+] Cleaned build files."

run: $(TARGET)
	@echo "[+] Running Jennet..."
	sudo ./$(TARGET)

# -----------------------------
# Checks
# -----------------------------
check_deps:
	@echo "[+] Checking prerequisites..."
	@if ! command -v $(CXX) &>/dev/null; then \
		echo "[!] Error: g++ compiler not found."; \
		exit 1; \
	fi
	@if [ ! -f "$(PCAPPP_DIR)/lib/libPcap++.a" ]; then \
		echo "[!] Error: PcapPlusPlus libraries not found at $(PCAPPP_DIR)/lib/"; \
		exit 1; \
	fi
	@if ! pkg-config --cflags Qt5Widgets &>/dev/null || ! pkg-config --libs Qt5Widgets &>/dev/null; then \
		echo "[!] Error: Qt5Widgets not found. Install qtbase5-dev and qtbase5-dev-tools."; \
		exit 1; \
	fi
	@echo "[+] All prerequisites OK."
