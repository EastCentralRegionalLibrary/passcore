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
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm --version \
    && node --version \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN dotnet publish Unosquare.PassCore.Web.csproj \
    -c Release \
    -o /app \
    /p:PASSCORE_PROVIDER=LDAP

# ---- runtime stage ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./

EXPOSE 80
ENTRYPOINT ["dotnet", "Unosquare.PassCore.Web.dll"]