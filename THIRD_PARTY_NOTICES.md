# Third-party notices

VPNCheck Stand itself is released under the [MIT license](LICENSE). It includes or downloads the
following third-party components, each under its own license.

## Included in this repository

| Component | Where | License |
|---|---|---|
| [Leaflet](https://leafletjs.com) 1.9.4 | `stand/ui/assets/leaflet/` (JS, CSS, images) | BSD-2-Clause, see [`stand/ui/assets/leaflet/LICENSE`](stand/ui/assets/leaflet/LICENSE) |
| [Natural Earth](https://www.naturalearthdata.com) 1:110m Admin 0 - Countries | `stand/ui/assets/world110m.geojson` | public domain |
| [Natural Earth](https://www.naturalearthdata.com) 1:10m Admin 1 - States, Provinces (Russia, simplified, Russian names added) | `stand/ui/assets/ru_regions.geojson`, also served by the agent server | public domain |
| Gradle Wrapper | `agent/gradlew`, `agent/gradlew.bat`, `agent/gradle/wrapper/` | Apache-2.0 |

Natural Earth: "Made with Natural Earth. Free vector and raster map data @ naturalearthdata.com."

## Downloaded by `tools/fetch_binaries.py` (not stored in the repository)

| Component | Where it ends up | License |
|---|---|---|
| [Xray-core](https://github.com/XTLS/Xray-core) (official release, version pinned in `stand/dcprobe.py`) | `bin/xray` (pushed to stand phones), `agent/app/src/main/jniLibs/arm64-v8a/libxray.so` (inside the agent APK), `/opt/vpncheck-stand` on the DC probe | [MPL-2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE) |
| `geoip.dat`, `geosite.dat` from the same Xray-core release | `bin/` | see the Xray-core release and [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) |

The Xray-core binary is used unmodified; its source code is available at
<https://github.com/XTLS/Xray-core>. If you distribute the agent APK, you distribute Xray-core
under MPL-2.0 together with it.

## Libraries installed by pip or Gradle (not stored in the repository)

- Stand (`requirements.txt`): PySide6 / Qt (LGPL-3.0), paramiko (LGPL-2.1), segno (BSD-3-Clause),
  cryptography (Apache-2.0 or BSD-3-Clause).
- Agent server (`server/requirements.txt`): FastAPI (MIT), Uvicorn (BSD-3-Clause), python-multipart
  (Apache-2.0), cryptography (Apache-2.0 or BSD-3-Clause).
- Agent (`agent/app/build.gradle.kts`): AndroidX, Kotlin and kotlinx.coroutines, OkHttp, Bouncy Castle,
  Google Play services location and Firebase Cloud Messaging - under their own licenses (Apache-2.0
  for most, MIT-style for Bouncy Castle, Android SDK terms for Google Play services and Firebase).

## Online services and map data

The maps load tiles at run time: Esri (World Dark Gray, World Imagery and others - Esri terms of use),
OpenStreetMap (© OpenStreetMap contributors, ODbL) and, if configured, Yandex Maps (Yandex terms of use).
Attribution is shown on the map. The agent server uses ipinfo.io and OpenStreetMap Nominatim, see
[SECURITY.md](SECURITY.md#known-limitations).
