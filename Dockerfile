FROM ghcr.io/calamity-inc/soup:4538b1ce2565ddab826d822cef7469cc0e6c72d8

# Compile app
COPY main.cpp /app
WORKDIR /app
RUN clang main.cpp -DDOCKER -LSoup -lsoup -ISoup/soup -std=c++17 -lstdc++ -fno-rtti

RUN mkdir conf

ENTRYPOINT ["./a.out"]
