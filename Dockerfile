# ---- build stage ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Ensures that if any part of a pipe fails, the build fails
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install Node (required by MSBuild targets)
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    build-essential \
    python3 \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm --version \
    && node --version \
    && rm -rf /var/lib/apt/lists/*

# Install Rust Toolchain (Required for native modules like LMDB)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path

WORKDIR /src
COPY . .

RUN dotnet publish src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj \
    -c Release \
    -f net8.0 \
    -o /app \
    /p:PASSCORE_PROVIDER=LDAP

# ---- runtime stage ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./

EXPOSE 80
ENTRYPOINT ["dotnet", "Unosquare.PassCore.Web.dll"]