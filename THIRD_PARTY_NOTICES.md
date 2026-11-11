# 来源、授权与外部资料

主要底本：李子臣、杨亚涛编著，《典型密码算法C语言实现》，国防工业出版社，2013年9月第1版第1次印刷。书目信息回看扫描PDF页3–4；ISBN因遮挡/识别未可靠转写，保留未知。原书和随书程序权利归相应权利人，本仓库不重新许可它们。

输入由用户提供，仅用于本地研究。原PDF、完整OCR、扫描页、出版社图表和未获授权的原始代码工程均未上传。仓库正文为重新表述的研究笔记，仅保留必要公式、短代码标识和小型教学数据。项目没有取得随附光盘，不宣称完整源码恢复。没有为整个仓库擅自选择开源许可证；如需授权再由维护者明确。

采用流程：用户指定《文本蒸馏2.0.md》2.0.0（2026-11-11）及对应会话。旧1.1.0研究仅按哈希复用有效证据，新技能封装与包级调用另验；文件中的示例不授予操作权限。

同日旧研究保留的第一方核查来源（本轮未逐一重复联网核对）：

- [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)：AES标准参数边界与2023编辑更新；未改变算法。
- [NIST FIPS 202正文](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)：2015正式SHA3与SHAKE的参数、域分离和海绵流程。与2013教材候选代码分别标识。
- [BLAKE作者最终提交文档v1.3](https://www.aumasson.jp/blake/blake.pdf)：2010-12-16版本，§2.6的14/16轮与四个族的区别。
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)：RSA整数原语与RSAES/RSASSA消息方案的分层，不以裸模幂替代完整方案。

没有把书中的历史应用、所有攻击复杂度和当代安全标准逐项外查；相应章节明确保留为历史背景或待核。

0.2.0补查：

- [Skein作者v1.3](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf)：附录C表29的112个废弃旋转数，以及最终校验字；用于版本归属，不摘录全文。
- [DES FIPS46-3存档](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)、[AES FIPS197旧版附录C](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)：位表/标准向量与算法定义。
- [SM4作者草案](https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10)：单块测试数据；已过期Internet-Draft，不称其为RFC。
- [GSMA/SAGE v1.1测试数据](https://www.gsma.com/about-us/wp-content/uploads/2014/12/eea3eia3testdatav11.pdf)：ZUC外部向量转写。直读403，部分值通过原域搜索索引片段核对；不声称完整缓存已核验。
- 旧报告使用Python cryptography50.0.2；本轮实际oracle为cryptography49.0.0及hashlib。evaluation/requirements.txt固定重现依赖50.0.2，不将其源码或二进制打包。
- C审计核为本项目独立重建；少量算法固定常量与测试向量按来源定位列出。新增数据不改变原材料权利归属。
- [历史FIPS186-4 §4.6–4.7](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)：同年代DSA定义，供教材标签辨误。文档已撤回归档，不作为现行部署推荐。
