FROM ghcr.io/calamity-inc/soup:6be2387cb68b71a2b1e2f1e7473501cf17c2b0ca

RUN mkdir conf
COPY cert /app/cert

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti -O3

ENTRYPOINT ["./a.out"]
