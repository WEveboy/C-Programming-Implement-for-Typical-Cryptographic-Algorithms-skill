# 独立重建的 C 数值审计核

`audit_cli.c`以教材机制为线索、按明确的算法定义重新编写，用于核对转写常量、字节布局和运行时序。不是作者光盘源码恢复，也不是生产密码库。

| 对象 | 实际接口与验证范围 | 尚不覆盖 |
|---|---|---|
| DES | 8字节单块加解密；经典向量和独立库对拍 | 三重DES、文件格式、部署策略 |
| AES | 16字节单块；128/192/256位密钥；FIPS向量和独立库对拍 | 工作模式、认证、硬件或恒定时间实现 |
| SM4 | 单块加解密、32轮密钥/状态跟踪；书例和独立库对拍 | 文件模式、随机IV、完整性 |
| ZUC | key/IV各16字节，初始化后输出前两个32位字；三组外部数据 | 任意长度流、分片接口、EEA3/EIA3封装 |
| Keccak/SHA3 | 1600位置换；SHA3四档及旧Keccak-256的字节对齐一次性摘要 | SHAKE、bit级输入、增量API、教材全部旧参数组合 |

需要C11编译器、Python 3.10以上；重现依赖固定为`cryptography==50.0.2`，本轮实跑使用已有49.0.0且全部对拍通过。旧本地记录为Python 3.12.14，本轮C对拍使用Python 3.14.6；GCC 16.2.0（i686），两个优化等级均使用`-Wall -Wextra -Wpedantic -Werror`。运行：

```text
python -m pip install -r evaluation/requirements.txt
python scripts/audit_constants.py
python scripts/run_c_audit.py --cc gcc
```

或手动编译与调用：

```text
python scripts/generate_constant_header.py
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror reference-c/audit_cli.c -o audit
./audit aes enc 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff
./audit sha3-256 enc "" 616263
```

Windows中可输出为`audit.exe`并用`.\audit.exe`调用。参数均为连续十六进制，摘要的密钥参数为空字符串。固定块接口拒绝不匹配的长度；十六进制无效、算法/方向无效返回2。输入缓冲上限8192字节，测试最大4096字节；命令行长度还受宿主限制。

`constants.h`只从`research/constants/`生成，避免两处独立维护同一表。C源码中的FK、D、轮常量、矩阵和旋转仍是显式常量或公式；生成表的审计强度见[常量台账](../research/CONSTANT_REVIEW.md)。

`run_c_audit.py`先冻结输入与独立oracle期望，再编译和执行C程序。864项是两档编译各432项，不能理解为864条彼此独立的标准向量；每档包括393个输出比较、32个SM4逐轮比较、7个拒绝测试。DES的库oracle使用三份相同8字节密钥的TripleDES EDE，代数上退化为单DES；这是一条独立实现对照，不是三重DES能力测试。

日志保留编译器版本、参数、源/头/计划/脚本哈希和每项实际输出。公开的Windows报告是一个固定快照，CI重跑会产生不同可执行文件哈希，不要求跨平台二进制相同。查表访问会依赖秘密数据；内存消毒器和侧信道未验收。Windows GCC的UBSan链接因缺`libubsan`失败，未计为通过。
