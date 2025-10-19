FROM ghcr.io/calamity-inc/soup:cd332ecef8ff3fa81fef5cffc7a07ab98d7b9a79

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
