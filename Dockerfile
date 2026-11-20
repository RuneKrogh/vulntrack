# Everything is installed and built inside containers, so nothing from npm or NuGet runs on the host.

FROM node:26-alpine AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS backend
WORKDIR /src
COPY global.json ./
COPY backend/Directory.Build.props backend/
COPY backend/VulnTrack.Api/VulnTrack.Api.csproj backend/VulnTrack.Api/
RUN dotnet restore backend/VulnTrack.Api/VulnTrack.Api.csproj
COPY backend/VulnTrack.Api/ backend/VulnTrack.Api/
RUN dotnet publish backend/VulnTrack.Api/VulnTrack.Api.csproj -c Release --no-restore -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=backend /app ./
COPY --from=frontend /src/dist ./wwwroot
# The .NET images ship with a non-root user.
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "VulnTrack.Api.dll"]
