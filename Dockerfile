# syntax=docker/dockerfile:1

# The repo is a Flutter mobile UI with no server and no web/ folder, so the image
# builds it as a Flutter *web* app and serves the static output with nginx.
# Flutter web needs SDK >= 2.0; the code is pre-null-safety (Dart < 2.12 language
# mode), which Flutter 2.x still compiles. Pin by tag here; pin by digest for releases.
# Why 2.5.3: the app calls BottomNavigationBarItem(title: ...) (lib/widgets/
# BottomNavBarWidget.dart), a parameter removed in later 2.x - 2.10.5 fails to compile.
# cirrusci/flutter is no longer updated. It was used because its 2.x tags exist on Docker
# Hub; ghcr.io/cirruslabs/flutter:2.10.5, :2.10.0 and :3.0.0 were checked and do not
# exist (its other tags were not enumerated). It is only the build stage: nothing from
# it ships in the final image.
ARG FLUTTER_IMAGE=cirrusci/flutter:2.5.3
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27-alpine

# ---- build stage (discarded; not part of the final image) ----
FROM ${FLUTTER_IMAGE} AS build
WORKDIR /app

# Dependencies first so this layer is cached until pubspec changes.
COPY pubspec.yaml pubspec.lock ./
RUN flutter pub get

COPY lib ./lib
COPY assets ./assets

# Generate the missing web/ scaffold inside the container only (repo stays untouched),
# then build. The html renderer is self-contained; the default CanvasKit renderer
# downloads its wasm from a CDN at runtime, which would be an external dependency.
RUN flutter create --platforms=web --project-name flutter_app . \
 && flutter build web --release --web-renderer html

# ---- runtime stage ----
FROM ${NGINX_IMAGE}

# Patch OS packages: the base image is rebuilt only occasionally, and Trivy found 58
# fixable HIGH/CRITICAL CVEs in its Alpine packages. Root is needed only for this step.
USER root
RUN apk upgrade --no-cache

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/build/web /usr/share/nginx/html

# Back to the base image's non-root user (uid 101). It listens unprivileged on 8080
# and writes only to /tmp.
USER 101
EXPOSE 8080

# Keep stdout to JSON access-log lines only: silences the base image's entrypoint chatter.
ENV NGINX_ENTRYPOINT_QUIET_LOGS=1

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
