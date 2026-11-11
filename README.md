# C for typical cryptographic algorithms skill

从李子臣、杨亚涛《典型密码算法C语言实现》（2013）蒸馏的研究试用技能，按《文本蒸馏2.0》整理描述、实现、来源纠错与可执行核验。覆盖13章、17个算法对象：ZUC、DES、AES、SM4、MH、RSA、Paillier、NTRU、ElGamal、ECC、SM2、McEliece及五个SHA-3决赛候选。

## 使用

将完整的[`skills/c-for-typical-cryptographic-algorithms-skill`](skills/c-for-typical-cryptographic-algorithms-skill/SKILL.md)目录放入宿主技能发现目录，再重载宿主。不要只复制入口。全局安装未在本任务执行；完整副本的资源加载和工具执行单独验证。

显式调用：
```text
使用 $c-for-typical-cryptographic-algorithms-skill 审查AES逆变换的布局与循环条件，给出来源页码和验证方法。
```

也可提供算法、版本、参数和C代码，要求解释、精确复算、移植或优化验证。参考[快速开始](docs/QUICKSTART.md)。

## 可执行范围

- 七类受预算限制的精确教学运算：RSA、Paillier、MH、ElGamal、ECC标量乘、NTRU和小码最近邻译码。
- 独立C审计核：DES、AES-128/192/256、SM4、ZUC前两个输出字、一次性字节对齐Keccak/SHA3。
- 来源审查：13章描述/实现双线索、可见代码逐单元分析、原书错误与OCR错误分开登记。
- 等价优化流程：固定版本、输入表示、输出和失败行为，再做差分；没有实测不宣称提速。

完整光盘工程缺失；本项目没有编译原书完整程序。完整公钥C库、EEA3/EIA3、其他四种候选Hash、任意分片API、侧信道和生产安全不在已验收范围。教学NTRU/McEliece不能替代现代KEM规范。历史Keccak与正式SHA3、旧BLAKE/Skein常量必须分别绑定。

验证结果与独立执行范围见[验收报告](docs/VALIDATION.md)，流程和证据分层见[2.0执行记录](docs/WORKFLOW_2.0.md)。研究试用不等于安全认证。

## 分发与来源

原PDF、全文OCR、页面图像和私有日志不上传。公开文件按白名单冻结，逐文件SHA256与Git对象核验。来源权利归原权利人，本项目未擅自授予整库开源许可，见[来源说明](THIRD_PARTY_NOTICES.md)。上传终点为可核验主题分支/PR；不自动合并或创建GitHub Release。
