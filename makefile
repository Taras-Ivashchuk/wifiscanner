TARGET=wifiscan
GCC=gcc
CFLAGS=-Wall -g `pkg-config --cflags libnl-genl-3.0`
LDFLAGS += `pkg-config --libs libnl-genl-3.0`
SOURCES_C=main.c wf80211_api.c
OBJECTS_C=$(SOURCES_C:.c=.o)

.PHONY: clean

all: $(TARGET)

$(TARGET): $(OBJECTS_C)
	$(GCC) -o $@ $(OBJECTS_C) $(LDFLAGS)

%.o: %.c
	$(GCC) $(INCLUDES) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ./*.o
	rm -f ./$(TARGET)
