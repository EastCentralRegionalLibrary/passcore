# ---- build stage ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# Install Node (required by MSBuild targets)
RUN apt-get update \
    && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
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