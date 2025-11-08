FROM ghcr.io/calamity-inc/soup:71ba0dcda84ba4a96fe76e132983e2996826fb29

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
