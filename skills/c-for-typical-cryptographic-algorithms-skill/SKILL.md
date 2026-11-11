---
name: c-for-typical-cryptographic-algorithms-skill
description: 基于《典型密码算法C语言实现》的逐章来源与纠错，解释算法、审查C移植、精确复算教学实例并验证等价优化。适用于ZUC、DES、AES、SM4、教材公钥算法和五种SHA-3候选的机制、表示与代码差异；现代协议部署须另选规范。
---

# C for typical cryptographic algorithms skill

先识别算法、版本、参数、消息表示与任务（解释、实现、复算、审查、优化）。所有相对路径从本文件所在目录解析。输出必须区分原书陈述、编辑重建、本次实跑与历史证据。

需要整书脉络时读[蒸馏阅读稿](research/DIGEST.md)；遇到单位元、中心提升、码距等术语时读[词典](research/GLOSSARY.md)。三项任务的范围和证据登记在[能力事实源](references/capabilities/catalog.json)。

## 路由

先查[17算法契约](docs/ALGORITHM_CONTRACTS.md)对应行，再按需读取以下章节，避免一次加载全书：

| 请求对象 | 描述与实现研读 |
|---|---|
| ZUC、EEA3/EIA3区别 | [01](docs/chapters/01-zuc.md) |
| DES、三重DES | [02](docs/chapters/02-des.md) |
| AES三档、S-AES区别 | [03](docs/chapters/03-aes.md) |
| SM4 | [04](docs/chapters/04-sm4.md) |
| MH背包 | [05](docs/chapters/05-mh.md) |
| RSA | [06](docs/chapters/06-rsa.md) |
| Paillier | [07](docs/chapters/07-paillier.md) |
| 教材NTRU | [08](docs/chapters/08-ntru.md) |
| ElGamal及签名辨误 | [09](docs/chapters/09-elgamal.md) |
| ECC两种消息表示 | [10](docs/chapters/10-ecc.md) |
| SM2加密链 | [11](docs/chapters/11-sm2.md) |
| McEliece矩阵与译码 | [12](docs/chapters/12-mceliece.md) |
| BLAKE/Grøstl/JH/Keccak/Skein | [13](docs/chapters/13-hash.md) |

## 执行契约

1. 解释或审查：读取[来源审查卡](references/capabilities/source-review.md)与[可见代码复核](research/CODE_REVIEW.md)有关单元。逐项连接“输入对象→表示→步骤→不变量→正确性→代码→失败条件”。页码以2013底本印刷页为准，PDF物理页加13；原PDF不随包分发，没拿到原页时引用包内研读记录，不能声称重新看过原页。
2. 精确复算：按[有限实例卡](references/capabilities/exact-instances.md)先检查合法性，再用`scripts/exact_instance.py`从标准输入读JSON。七个对象分别为`rsa / paillier / mh / elgamal / ecc / ntru / mceliece-toy`。输入字段与限制见卡片；拒绝返回码2。该脚本是小参数教学运算器，不采样密钥、不实现文件加密或完整SM2。
3. C实现或优化：按[C核与等价优化卡](references/capabilities/c-equivalence.md)固定算法/版本/端序/接口/错误行为，保留易审查基线，再比较输出及中间状态。参考[C路线](docs/C_IMPLEMENTATION_PLAN.md)定义缓冲、别名、状态所有权、随机数及失败契约。新写代码标为独立重建，缺失作者函数体不能臆补成原工程。

运行会写报告或构建文件时，先将完整Skill复制到当前任务的隔离工作目录。从副本运行所需脚本，安装目录保持固定参考。精确算术只需Python 3.10+；C审计需C11编译器，差分oracle另需cryptography。依赖及命令见[审计核说明](reference-c/README.md)。只有本次成功执行后才能声称本次通过。

## 必查差异

- ZUC区分31位模加与32位回绕，32轮初始化后有一次丢弃轮。EEA3/EIA3另有协议位序和IV约定。
- DES解密先IP、最后IP逆，轮密钥逆序；书中初始置换文字有误。AES列优先、末轮省MixColumns，原页InvSubBytes循环条件有错。
- SM4的L和L′不同；末四字反序；指针强转不能替代明确端序加载。
- Paillier的r必须是单位元；原书r=42非法，算式r=23才对应4624。NTRU必须中心提升；ElGamal跨独立密文复用k会泄漏比值。
- ECC域消息与点消息分开。SM2可见四坐标代码缺KDF/C3认证链，不能作为完整SM2实现。
- McEliece小码最近邻不等于大参数Goppa译码。BLAKE旧轮数、Skein旧常量、Keccak的0x01域与正式SHA3的0x06必须分别绑定。BLAKE/JH分片及末位问题见[纠错台账](research/SOURCE_CORRECTIONS.md)。

## 输出与验收

给出结果或代码、输入/版本/表示、来源定位与推导、实际执行命令与结果、仍影响任务的具体缺口。优化须保持失败行为与消息编码；计时区分密钥设置、核心计算与I/O，没有实测就只给方案。安全性、参数族正确性与有限实例通过分别论证。

## 范围

本包为研究试用级，支持知识路由和限定计算任务。C审计接口为DES单块、AES三档单块、SM4单块/轮跟踪、ZUC前三组向量的前两个字、字节对齐一次性Keccak/SHA3。完整光盘工程、完整公钥C库、其他四候选Hash、EEA3/EIA3、任意分片API、侧信道及生产安全未验收。旧58候选台账保留原裁决；新三张能力卡与新评测另行登记，不提升旧来源的证据等级。包复制与工具执行已测，宿主自动发现/全局安装状态须据实报告。
