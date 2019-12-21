TARGET=crossnet_server

OBJECTS:=$(patsubst %.c,%.o,$(wildcard *.c))

GIT_COMMIT_ID=`git rev-list HEAD --max-count=1`
MAKE_TIME=`date +%Y_%m_%d_%H:%M:%S`

ifndef VERSION
	VERSION="1.0"
endif

THIS_VERSION=\"v$(VERSION)-$(GIT_COMMIT_ID)-$(MAKE_TIME)\"
CFLAGS = -DVERSION=$(THIS_VERSION)

COPTIONS = -fPIC -Wall -rdynamic -O0 -g

CINCDIRS = -I/usr/include/mysql
LINKLIBS = -L/lib64/mysql -L/usr/local/lib -lmysqlclient -lpthread -lz -lcrypto -ljson-c -lcurl -liconv

CFLAGS += $(COPTIONS) $(CINCDIRS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LINKLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	$(RM) $(TARGET) $(OBJECTS)
