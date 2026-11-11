# C02 有限实例精确复算

## R
来源：MH印刷85—92、RSA97—111、Paillier114—121、NTRU125—131、ElGamal135—141、ECC146—156、McEliece183—194。程序为独立教学重建，原书实例与合成测试分开。
## I
先核输入域与逆元，再在整数/有限域/循环环上直接计算；将恢复结果对照规范化明文。拒绝非法输入比继续得到一个整数更有意义。
## A1
原例：RSA(p,q,e,m)=(43,59,13,224)→1692；Paillier(n,g,m,r)=(77,5652,42,23)→4624。合成演练：RSA(11,17,7,42)及r与n不互素的Paillier，预期独立冻结于评测。
## A2
触发：小参数复算、找反例、验证中心提升/矩阵/群点。完整C方案转C03；历史论述转C01。
## E
运行`python scripts/exact_instance.py`，向标准输入传一个JSON对象，读取`status/result`或`status/reason`；失败退出2，无随机采样。公共字段`algorithm`与分支字段：

| algorithm | 字段 | 检查和确定步骤 |
|---|---|---|
| rsa | p,q,e,message | 不同素数，e与φ互素，m在[0,n)；求d、c=m^e modn及c^d |
| paillier | p,q,message,r；可选g默认n+1 | 不同奇素数，r/g单位元、L(g^λ)可逆；加密、精确整除L后解密 |
| mh | private,modulus,multiplier,bits | 超递增、N>总和、w可逆；生成公钥、子集和、逆乘后降序贪心 |
| elgamal | p,g,private,nonce,message | 全乘法群原根及合法标量/非零消息；计算y、(g^k,m*y^k)、逆乘恢复 |
| ecc | p,a,b,point,scalar | p>3、非奇异、合法点（null为无穷远）；加倍相加求标量乘；不冒充SM2 |
| ntru | p,q,f,g,fp,fq,r,message | 向量按常数项到高次；检查双模逆；h=fq*g，c=p*r*h+m；f*c中心提升再乘fp模p |
| mceliece-toy | generator,ciphertext,t | 私有码G，检查满秩/码距≥2t+1；枚举码字，唯一半径内消息。未包含S/P掩蔽或Goppa译码 |

数值预算：素数≤65535；向量长度≤32；McEliece k≤10；一般整数≤2^64−1；ECC标量≤2^32−1；输入JSON≤64KiB。NTRU偶q中心区间[-q/2,q/2)，需证明整数卷积不越界，否则拒绝。明文按模p系数恢复，不承诺保留任意整数代表。输出大整数私钥仅供教学，不能用于真实密钥。

示例（在Skill副本根目录运行）：
```text
echo {"algorithm":"rsa","p":11,"q":17,"e":7,"message":42} | python scripts/exact_instance.py
```
PowerShell建议用单引号包住整段JSON再管道传入。完成标准：合法输入结果满足对应恢复恒等式，边界明确拒绝；未知算法不静默替换。
## B
这是受预算限制的精确运算，不是大参数密码库、安全采样器或完整编码方案。MH、裸RSA、教材NTRU和小码只用于学习。原始40项回归中的两项来源冲突保持不匹配，不能改预期消除。
