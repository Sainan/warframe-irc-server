FROM ghcr.io/calamity-inc/soup:62916a48261666b74196e02655485c2af4e623fe

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++20 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
