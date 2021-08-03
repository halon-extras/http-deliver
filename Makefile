all: http-deliver

http-deliver:
	g++ -L/usr/local/lib/ -I/opt/halon/include/ -I/usr/local/include/ -fPIC -shared http-deliver.cpp -lcurl -o http-deliver.so
