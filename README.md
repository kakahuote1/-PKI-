# TinyPKI

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-brightgreen.svg)]()

TinyPKI 是一个面向资源受限设备、弱连接网络和边缘节点的轻量级 PKI 核心库。它使用 C11 和 OpenSSL 3.x EVP 接口实现，围绕 SM2/SM3/SM4、ECQV 隐式证书、Merkle 证明和边缘见证机制，提供从证书签发、撤销校验到认证会话保护的完整主链路。

项目目标不是替代 TLS、HSM 或完整 WebPKI 生态，而是在 IoT 和边缘计算场景中提供更小的证书载荷、更少的在线依赖、可离线验证的撤销状态，以及可约束 CA 行为的发证透明能力。

## 设计重点

- **ECQV 隐式证书**：设备证书只携带必要恢复信息，验证端根据 CA 公钥重构设备公钥，降低证书编码和传输开销。
- **路径压缩 sparse Merkle 撤销树**：CA 用撤销根承诺当前撤销状态，设备携带 member 或 absence proof，对端可离线验证证书是否被撤销。
- **追加式发证记录树**：CA 按签发顺序写入证书承诺，使用 MMR（追加式 Merkle Mountain Range）维护发证记录，避免普通 Merkle 树在持续追加场景中的重复重构。
- **统一证据包**：一次认证携带证书、撤销证明、发证证明、CA 签名根记录和边缘 witness 签名，验证端用同一个检查点完成联合验证。
- **边缘 witness 门限**：验证端强制检查 `t-of-n` witness policy，只有足够多边缘节点签过同一个 CA 发布根时，证据包才被接受。
- **撤销广播与同步**：支持 `nextUpdate`、delta 更新、heartbeat 续期、full checkpoint、重定向候选和 quorum 检查，用于弱网和边缘分区场景。
- **认证即加密**：身份验证、用途检查、撤销检查和握手绑定通过后，可派生会话密钥并使用 SM4-GCM/CCM 进行 AEAD 保护。

## 系统角色

TinyPKI 默认围绕三类角色设计：

- **轻量化设备**：保存自身证书、私钥、可信 CA 信息、最近验证过的 CA 发布根和必要的本地持久状态。
- **边缘节点**：缓存撤销状态和发证状态，生成证据包，可作为 witness 对 CA 发布根签名。
- **CA**：签发 ECQV 证书，维护撤销树和发证记录树，定期发布带签名的根记录。

验证时，轻量化设备不需要在线查询 CA。它只需要使用本地可信 CA 根记录，验证对方携带的证据包是否能重新计算到同一个 CA 签名根。

## 仓库结构

```text
include/                 公开头文件
src/ecqv/                ECQV 隐式证书实现
src/revoke/              撤销状态、Merkle 证明和同步逻辑
src/pki/                 CA/RA 服务端、客户端和证据包主流程
src/auth/                认证、密钥协商和 AEAD 会话保护
src/app/                 demo 与 benchmark 程序
tests/                   单元测试和集成测试
tools/                   格式检查脚本
docs/                    安装说明、安全模型和审计记录
```

## 快速构建

依赖：

- C11 编译器：GCC、Clang 或 MSVC 兼容工具链
- CMake 3.14 或更高版本
- OpenSSL 3.x 开发库

Linux：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
./build/test_all
```

Windows MSYS2 UCRT64：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
./build/test_all.exe
```

更完整的环境说明见 [docs/install.md](docs/install.md)。

## 运行演示

证书生命周期主链路：

```bash
cmake --build build --target sm2_test_cert_flow -j 4
./build/sm2_test_cert_flow
```

撤销 Merkle 证明演示：

```bash
cmake --build build --target sm2_test_merkle_flow -j 4
./build/sm2_test_merkle_flow
```

Windows 环境下可使用对应的 `.exe` 后缀。

## 测试与基准

当前自动化基线包含 6 个 `ctest` suite 和 108 个 `test_all` 聚合用例：

```bash
ctest --test-dir build --output-on-failure
./build/test_all
```

格式检查：

```bash
# Windows PowerShell
./tools/check_format.ps1

# Linux / CI
bash tools/check_format.sh
```

能力实验集：

```bash
cmake --build build --target sm2_bench_capability_suite -j 4
./build/sm2_bench_capability_suite ./tmp/bench_capability_suite.json
```

`sm2_bench_capability_suite` 会输出 TinyPKI 主链路结果，并与 CRL、OCSP 和 CRLite 风格级联 Bloom filter 做本地对照。输出 JSON 同时包含固定 seed、commit、平台、编译器、预热轮数、正式测量轮数、median、p95、均值、标准差和稳定性标记。README 不固定写死性能数字，正式数据以当前 commit 运行出的 benchmark 报告为准。

## 作为依赖使用

TinyPKI 当前提供静态库目标 `tinypki`。在上层项目中可通过 CMake 子目录或子模块方式接入：

```cmake
add_subdirectory(TinyPKI)
target_link_libraries(your_app PRIVATE tinypki)
```

推荐从高层 PKI 接口接入，不建议应用代码直接组合内部认证和撤销树原语。

主要公开头文件：

- `include/sm2_tinypki.h`：推荐的一站式入口。
- `include/sm2_implicit_cert.h`：ECQV 请求、签发、验证和密钥重构。
- `include/sm2_revocation.h`：撤销根记录、证明、同步计划和仲裁辅助能力。
- `include/sm2_pki_transparency.h`：发证透明、统一根记录和 witness policy 类型。
- `include/sm2_pki_service.h`：面向 CA/RA 服务端的高层接口。
- `include/sm2_pki_client.h`：面向轻量化设备的高层接口。
- `include/sm2_auth.h`：公开签名类型和 AEAD 模式常量。
- `include/sm2_pki_types.h`：统一错误码和公共基础类型。

## 安全边界

TinyPKI 的安全设计默认攻击者可以监听、篡改、重放或延迟网络流量，也可以控制部分边缘节点。验证端不会信任边缘节点直接给出的结论，而是重新计算证明并比对本地可信的 CA 签名根。

仍需由部署环境承担的边界包括：

- 私钥长期托管应优先使用安全芯片、可信执行环境或等价硬件能力。
- 如果攻击者能把设备本地存储整体回滚到旧快照，且设备没有安全计数器、可信时钟或其他不可回滚小状态，纯软件无法证明该快照不是旧状态。
- TinyPKI 提供面向本项目角色的紧凑发证透明机制，不包含完整 WebPKI CT 生态中的公共日志、浏览器强制策略和独立监控网络。

更多内容见 [SECURITY.md](SECURITY.md)、[docs/security/threat_model.md](docs/security/threat_model.md) 和 [docs/security/security_audit_v0.1.0.md](docs/security/security_audit_v0.1.0.md)。

## 项目文档

- [CHANGELOG.md](CHANGELOG.md)：当前 release-candidate 基线变更记录。
- [CONTRIBUTING.md](CONTRIBUTING.md)：贡献流程、检查命令和代码风格要求。
- [docs/install.md](docs/install.md)：构建、测试和 demo 运行说明。
- [SECURITY.md](SECURITY.md)：安全策略和漏洞报告流程。
- [docs/security/threat_model.md](docs/security/threat_model.md)：威胁模型。
- [docs/security/security_audit_v0.1.0.md](docs/security/security_audit_v0.1.0.md)：安全审计记录。

## License

TinyPKI is licensed under the [Apache License 2.0](LICENSE).

## Star History

<a href="https://www.star-history.com/?repos=kakahuote1%2FTinyPKI&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=kakahuote1/TinyPKI&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=kakahuote1/TinyPKI&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=kakahuote1/TinyPKI&type=date&legend=top-left" />
 </picture>
</a>
