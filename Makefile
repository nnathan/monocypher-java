# Default to host platform unless overridden
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ifeq ($(HOST_OS),darwin)
  JAVA_HOME ?= $(shell /usr/libexec/java_home)
  OUT_SUFFIX = "dylib"
else ifeq ($(HOST_OS),linux)
  JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which javac))))
  OUT_SUFFIX = "so"
else
  $(error Unsupported HOST_OS: $(HOST_OS))
endif
JNI_PLATFORM ?= $(HOST_OS)
CFLAGS += -fPIC
CFLAGS += -I"$(JAVA_HOME)/include"
CFLAGS += -I"$(JAVA_HOME)/include/$(JNI_PLATFORM)" -O3
LDFLAGS = -shared

SRC = monocypher.c monocypher_jni.c
OUT = libmonocypher_jni.$(OUT_SUFFIX)

all:
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(OUT)

clean:
	rm -f $(OUT)
