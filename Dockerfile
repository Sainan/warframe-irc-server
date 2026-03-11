FROM ghcr.io/calamity-inc/soup:55d7d976998f4d1c3139c529ee314d2b400b03b3

RUN mkdir conf
COPY cert /app/cert

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti -O3

ENTRYPOINT ["./a.out"]
