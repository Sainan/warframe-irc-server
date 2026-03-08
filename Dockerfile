FROM ghcr.io/calamity-inc/soup:4f09b8b139231e7c398a6725ebc408dd9ff44fc0

RUN mkdir conf
COPY cert /app/cert

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti -O3

ENTRYPOINT ["./a.out"]
