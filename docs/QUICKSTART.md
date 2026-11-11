# 从完整Skill副本开始

在仓库根目录，将`skills/c-for-typical-cryptographic-algorithms-skill`完整复制到本次任务可写目录。以下命令在副本根目录执行，Python至少3.10。

PowerShell精确复算（无额外依赖）：
```powershell
'{"algorithm":"rsa","p":11,"q":17,"e":7,"message":42}' | python scripts/exact_instance.py
```
应返回`status=ok`、ciphertext=15、recovered=42。将算法换成未支持名称应返回`status=rejected`和退出码2。其他六分支字段见`references/capabilities/exact-instances.md`。

重新运行有限书例：
```text
python scripts/verify_witnesses.py
python scripts/verify_followups.py
python scripts/audit_constants.py
```
40项中的2个来源冲突保留为不匹配；脚本只对意外失败返回错误。不能把38/40写成40项原期望全部通过。

C对拍另需C11编译器和cryptography：
```text
python -m pip install -r evaluation/requirements.txt
python scripts/run_c_audit.py --cc gcc
```
成功输出864/864，含两优化等级各432项。缺编译器或依赖先修环境，不把旧报告当本次实跑。脚本会写`evaluation/reports`、生成常量头及`tmp/build`；不在已安装技能目录直接重跑。

正常请求可直接说“审查这段SM4代码的端序、轮密钥和输出反序”，或“先为这个算法定义C接口与验证计划”。算法/版本缺失时，技能应先列缺失条件，不能静默选择另一算法。普通文件排序等近邻负例不需要密码技能。
