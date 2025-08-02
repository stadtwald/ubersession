../target/cgi/cgi-wrapper: ../target/cgi/crypto_api.o ../target/cgi/fe25519.o ../target/cgi/mod_ge25519.o ../target/cgi/sc25519.o ../target/cgi/mod_ed25519.o ../target/cgi/session_token.o ../target/cgi/cgi-wrapper.o
	cc ../target/cgi/crypto_api.o ../target/cgi/fe25519.o ../target/cgi/mod_ge25519.o ../target/cgi/sc25519.o ../target/cgi/mod_ed25519.o ../target/cgi/session_token.o ../target/cgi/cgi-wrapper.o -lmd -o ../target/cgi/cgi-wrapper

../target/cgi/cgi-wrapper.o: ./cgi-wrapper.c ./session_token.h
	cc ./cgi-wrapper.c -c -o ../target/cgi/cgi-wrapper.o

../target/cgi/session_token.o: ./session_token.c ./session_token.h ./crypto/crypto_api.h
	cc ./session_token.c -DVERIFYONLY=1 -c -o ../target/cgi/session_token.o

../target/cgi/crypto_api.o: ./crypto/crypto_api.c ./crypto/crypto_api.h
	cc ./crypto/crypto_api.c -DVERIFYONLY=1 -c -o ../target/cgi/crypto_api.o

../target/cgi/fe25519.o: ./crypto/fe25519.c ./crypto/fe25519.h ./crypto/crypto_api.h
	cc ./crypto/fe25519.c -DVERIFYONLY=1 -c -o ../target/cgi/fe25519.o

../target/cgi/mod_ge25519.o: ./crypto/mod_ge25519.c ./crypto/fe25519.h ./crypto/sc25519.h ./crypto/ge25519.h ./crypto/crypto_api.h
	cc ./crypto/mod_ge25519.c -DVERIFYONLY=1 -c -o ../target/cgi/mod_ge25519.o

../target/cgi/mod_ed25519.o: ./crypto/mod_ed25519.c ./crypto/ge25519.h ./crypto/crypto_api.h
	cc ./crypto/mod_ed25519.c -DVERIFYONLY=1 -c -o ../target/cgi/mod_ed25519.o

../target/cgi/sc25519.o: ./crypto/sc25519.c ./crypto/sc25519.h ./crypto/crypto_api.h
	cc ./crypto/sc25519.c -DVERIFYONLY=1 -c -o ../target/cgi/sc25519.o

