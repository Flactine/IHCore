# FA2sp 加密资源包读取

在 `IHCore.dll.json` 中与 `ExtraPath_First`、`FileRedirect` 同级添加：

```json
{
  "FA2ResourcePacks": ["Assets/data1.pack", "Assets/data2.pack"]
}
```

路径相对游戏可执行文件目录，也支持绝对路径。列表靠前的包优先。
显式文件流绑定与其他已注册过滤器优先；包内文件优先于普通磁盘文件和 MIX。
不配置此项不会加载资源包。日志中的 `[FA2Pack] loaded` 表示包头、绑定和索引验证通过；文件内容在打开时另行解密及验证。

## 配套代码

`IHCore/ResourcePack/Body.Cipher.h` 和 `Body.Encryption.cpp` 来自 FA2sp 的生成器。
当前版本复制自本地 FA2sp 工程，只能读取与该生成代码匹配的包。
发行时将生成器为你的所有包生成的这两个文件同时放入此目录，重新编译 IHCore。
FA2sp 与 IHCore 应使用同一组生成文件。无需在本项目另填种子。
生成文件可能包含发行专用的解密材料，发布源码时应换成测试版本。

## 构建与分发

支持 Release / Win32，使用 VS 2022 v143、C++20。

```powershell
$env:CL = '/MP8'
msbuild IHCore/IHCore.vcxproj /m /p:Configuration=Release /p:Platform=Win32 /p:SolutionDir="$PWD/"
```

构建后 `libcrypto-1_1.dll` 自动复制到输出目录。分发时将它与 IHCore 放在游戏目录。
依赖沿用 FA2sp 的 x86 OpenSSL 1.1（头文件、导入库和 DLL 位于 `libs/FA2Pack`）。
不要换成静态链接而不检查生成代码的导入验证。

## 行为与限制

- 文件名 ASCII 大小写不敏感；按打包时的文件名查询，不枚举文件名。
- 支持 Exists、Open、Read、Seek、Size、Close，只读；拒绝写入打开。
- 每次打开解密一个完整文件，Close 释放内存，不输出明文临时文件。
- 包索引及文件名查询标识缓存；包内容读取串行化以保护共享文件位置。
- 包加载失败记录日志并跳过。已命中的包文件若内容校验失败，打开失败，不转用同名低优先级资源。
- 这是游戏文件流接口的支持；直接绕过该接口的引擎/第三方代码需单独验证。
- 大型视频/音频会占用对应的完整文件内存，首版没有分块解密或全局明文缓存。

## 验证

`Tests/FA2Pack/Run.ps1 -Generator <generator.exe路径>` 在临时目录生成专用测试包和代码，
编译独立读取测试，不改动发行解密代码。覆盖内容往返、大小写、空文件、缺失文件、
多包、内容损坏、截断包、清理后重载和不匹配的发行代码。

完整游戏内载入需要配套发行包及游戏环境，独立测试不替代游戏内验证。

读取器移植自 FA2sp 的 `Body.ResourcePack.cpp`，保留原算法与校验，去除编辑器依赖。
FA2sp 来源：https://github.com/handama/FA2sp （GPL-3.0）。
