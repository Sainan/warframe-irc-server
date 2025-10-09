FROM ghcr.io/calamity-inc/soup:41c7572229d1bbbde0ea1a5bc9bc1474c09de082

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
