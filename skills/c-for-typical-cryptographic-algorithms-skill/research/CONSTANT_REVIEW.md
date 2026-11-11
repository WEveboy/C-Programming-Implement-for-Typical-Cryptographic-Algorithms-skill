# 常量与数值证据台账

页码均为印刷页，PDF物理页加13。数据由原页图像阅读转写，OCR不作为数值权威。表中“全表”指转写的条目范围，不等于两人盲录或所有输入已获得标准测试覆盖。脚本只验证所列代数/结构属性。

| 对象/位置 | 已固化内容 | 本轮证据与边界 |
|---|---|---|
| ZUC，4–5 | S0/S1各256字节；D在C源码列出16个15位值 | S盒各为全排列，D与原二进制表回看；三组key/IV的前2字匹配外部测试数据。尚未逐项与第二权威表自动对拍 |
| DES，24–30 | IP/逆、PC1/2、E/P、移位表、8×64 S盒 | IP复合、去奇偶位、S盒各行排列等检查；独立库新输入对拍与经典向量通过。结构检查不能独自证明每格是标准值 |
| AES，45/47/48/50 | 正逆S盒各256字节；Rcon按域乘生成；正逆列混合在C核表示 | 全256字节由GF逆元+仿射映射重算S盒；全256逆复合、4×4矩阵复合；三档密钥标准向量及独立库加解密一致 |
| SM4，72–77 | S盒256字节，书例32rk+32状态；FK在C列出、CK按公式生成 | 独立库新输入对拍；64个书例中间值一致。常量数据与书例分别保存，未只测round-trip |
| BLAKE，200–204 | sigma10×16和c32的16字 | 已转写、sigma各行为排列；10/14与最终14/16轮冲突已归属。未运行BLAKE，c64及各族IV未作为已验收常量交付 |
| Skein，223 | 三档置换和全部112个旋转数，旧/新校验常数 | 全部旋转与作者v1.3附录C的废弃表29人工逐行对照一致；置换全排列和范围检查。未因此断言书中未给出的Process_Block也属于同一版本 |
| Grøstl/JH，208–217 | 可见包装、长度与输出偏移 | 书中未完整给P/Q Transform、F8与全部置换常量；登记缺失，不用AES表或其他候选补作作者源码 |
| Keccak，218–221 | 书中padding/rate表达；C审计核另按FIPS202列24轮常量及25旋转 | 四档SHA3跨rate边界与hashlib一致，旧域空串另测；完整常量数组未在教材页面逐字给出，不将独立核表声称为书页转写 |
| 教学缩小版与公钥例，12–14/35–36/56–59/85–198 | 小例在章节或Python见证保存 | 与标准ZUC/DES/AES及大参数方案区分；(7,4,3)小码不升级为Goppa译码器 |

数值文件位于`research/constants/`，哈希绑定在`evaluation/reports/constant-audit.json`。`scripts/audit_constants.py`执行19项聚合检查；每项的元素数独立列出，不与C测试次数相加。生成头文件与C执行计划另由`c-audit.json`绑定。

外部依据：[AES FIPS197原版附录C](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)、[DES FIPS46-3存档](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)、[SM4作者Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10)（过期草案，非RFC）、[GSMA/SAGE测试数据v1.1](https://www.gsma.com/about-us/wp-content/uploads/2014/12/eea3eia3testdatav11.pdf)、[Skein作者v1.3](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf)。GSMA直读返回403，本轮第三组长key/IV及输出由搜索引擎收录的原域文档片段核对；没有伪造完整下载或本地规范缓存。三组均保留转写属性和有限覆盖边界。
