FROM ghcr.io/calamity-inc/soup:4ca93073fbbb548a0337126c79543ac54288be81

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
