# eval-cve-OOB.jsonl 漏洞模式提炼（OOB 类）

- 数据概况：85 个实例，CWE-125（越界读）50 个、CWE-787（越界写）35 个；ASan 类型分布：heap-buffer-overflow 66、stack-buffer-overflow 10、stack-buffer-underflow 2、global-buffer-overflow 1、SEGV 5。
- 目标：让阶段 1 的数据流总结更关注可控长度/偏移的传播，阶段 2 生成 PoC 时按模式选择构造手法。

## 常见模式与触发条件

### 1) MP4/ISO 箱体长度信任（GPAC 系）
- 触发流：比特流里的 box/entry 长度、计数或 grouping_type 在跨函数（`gf_isom_box_read`→`gf_isom_box_size` 等）未与剩余缓冲区比对，即被用来 `malloc/memcpy`、跳表合并或栈数组写入。
- PoC 思路：构造 mp4/ismv/moof 等箱体，注入 0/极大 size、负数到 size_t、extra bytes 或重复 sgpd/sbgp，诱导解析循环越界。
- 实例 ID：gpac.cve-2024-0321, gpac.cve-2023-0760, gpac.cve-2023-4721, gpac.cve-2022-3178, gpac.cve-2023-3291, gpac.cve-2024-0322, gpac.cve-2023-0866, gpac.cve-2023-4682, gpac.cve-2023-48014, gpac.cve-2023-0841, gpac.cve-2023-5998, gpac.cve-2023-0819, gpac.cve-2022-29537, gpac.cve-2023-46927, gpac.cve-2024-50664, gpac.cve-2023-4754, gpac.cve-2023-4758, gpac.cve-2021-32439。

### 2) DWG 记录长度/字符串拼接缺界（libredwg）
- 触发流：DWG 记录或字符串字段的长度/计数用于 `memcpy/strcat` 但缓冲区按原长或固定大小分配；部分路径还有 size 与 header 相减后的 underflow。
- PoC 思路：在 DWG 中设置过长字符串（特别是会被 HTML/URL 转义膨胀的字段）或错误计数，使复制/拼接超出分配。
- 实例 ID：libredwg.cve-2020-21816, libredwg.cve-2021-28237, libredwg.cve-2020-6614, libredwg.cve-2022-45332, libredwg.cve-2020-21814, libredwg.cve-2020-6612, libredwg.cve-2021-42585, libredwg.cve-2023-36273, libredwg.cve-2020-23861, libredwg.cve-2020-21818, libredwg.cve-2022-33034, libredwg.cve-2020-21819, libredwg.cve-2020-21827, libredwg.cve-2021-42586。
  - 其中纯字符串膨胀/拼接型：libredwg.cve-2020-21816, libredwg.cve-2020-21814, libredwg.cve-2020-21818, libredwg.cve-2020-21819, libredwg.cve-2020-21827。

### 3) 图像尺寸/步长算术溢出（ImageMagick / OpenJPEG / OpenEXR / libjpeg-turbo）
- 触发流：文件头给出的 width/height/components/resolution 进入乘法或行步长计算后用于栈/堆数组，没有对超大值或乘法溢出做上限；有些路径再用该尺寸做 memcpy/卷积。
- PoC 思路：构造超大或异常比例的尺寸/分量计数（BMP/JPEG2000/OpenEXR/MIFF 等），或设置 tile/strip 大小与实际数据不匹配，诱导行跨度或像素索引越界。
- 实例 ID：imagemagick.cve-2018-5248, imagemagick.cve-2019-13304, imagemagick.cve-2019-13305, imagemagick.cve-2017-11533, imagemagick.cve-2019-13299, imagemagick.cve-2019-13303, imagemagick.cve-2022-1115, imagemagick.cve-2019-13295, imagemagick.cve-2017-11540, imagemagick.cve-2019-13302, imagemagick.cve-2019-13297, imagemagick.cve-2022-0284, imagemagick.cve-2019-13298, imagemagick.cve-2019-13306, imagemagick.cve-2019-13300, openjpeg.cve-2024-56827, openjpeg.cve-2016-10507, openjpeg.cve-2021-3575, openjpeg.cve-2017-14041, openexr.cve-2020-16589, openexr.cve-2020-16587, libjpeg-turbo.cve-2020-13790。

### 4) 有符号/整数宽度混淆导致的越界
- 触发流：负数或大值从 `int32` 转为 `size_t`/`uint32` 后参与偏移/分配，或 `count * elem_size` 溢出回小缓冲；常见于长度字段的减法、箱体 size 校验、plist 计数、脚本索引。
- PoC 思路：在长度/计数字段提供 0x80000000、-1 或特大值，让加/减/乘出现 wrap 后被当作可信长度使用。
- 实例 ID：gpac.cve-2024-0321, gpac.cve-2024-0322, libredwg.cve-2022-45332, gpac.cve-2023-4682, gpac.cve-2023-5998, exiv2.cve-2017-17669, liblouis.cve-2023-26768, exiv2.cve-2020-18899, php.cve-2017-12933, njs.cve-2019-13617, gpac.cve-2023-4754, exiv2.cve-2018-17229, exiv2.cve-2018-17230, libplist.cve-2017-5545, exiv2.cve-2017-17723, openexr.cve-2020-16587, openjpeg.cve-2016-10507。

### 5) 解释器/迭代器索引缺界（脚本与文本处理）
- 触发流：用户可控的 index/count 驱动数组或 VM 字符串遍历，缺少 range check；含 JS VM、mruby、jq filter、PHP strxfrm/locale、MD 解析器、YARA 规则等。
- PoC 思路：提供超大 index/循环次数，或触发空/零长度路径让迭代器继续前进至越界。
- 实例 ID：njs.cve-2022-38890, njs.cve-2019-13617, mruby.cve-2022-0631, mruby.cve-2018-12248, mruby.cve-2022-0570, mruby.cve-2022-1286, php.cve-2017-12933, jq.cve-2023-50246, md4c.cve-2018-11545, yara.cve-2023-40857。

### 6) AAC 解码边界滑动（faad2）
- 触发流：帧头/通道配置/section 尺寸控制栈数组或频带循环，缺少对 frameLen/band 数的交叉校验，出现 stack-buffer-underflow/overflow。
- PoC 思路：在 AAC 比特流中篡改 frame length、channel config 或 section 长度，使解码循环跨过数组边界。
- 实例 ID：faad2.cve-2018-20194, faad2.cve-2018-20196, faad2.cve-2021-32272, faad2.cve-2018-20361, faad2.cve-2018-20197, faad2.cve-2021-32278。

### 7) 其他文件格式长度/偏移校验缺失
- 触发流：非 GPAC/图像的格式解析中将长度直接用于分配或跳转（libarchive tar/cpio、Exiv2 box 长度、MAT v5、plist、readstat、modbus PDU、DWARF 节点等），少了 “剩余字节/最大记录数” 的约束。
- PoC 思路：构造长度大于实际数据、或长度减 header 变负的字段；在多级嵌套盒子中交错超长与零长度触发错误路径。
- 实例 ID：libarchive.cve-2017-14503, libarchive.cve-2020-21674, exiv2.cve-2017-17669, exiv2.cve-2020-18899, exiv2.cve-2018-17229, exiv2.cve-2018-17230, exiv2.cve-2017-17723, matio.cve-2019-20018, matio.cve-2019-20017, libplist.cve-2017-5545, readstat.cve-2018-5698, libmodbus.cve-2022-0367, libdwarf.cve-2022-32200, libdwarf.cve-2022-34299, liblouis.cve-2023-26768。

## 对阶段化流程的启示
- 阶段 1（数据流总结）：优先跟踪“输入长度/计数 → 算术（加减乘）→ 分配/跳转/循环”链条，并记录是否有对剩余缓冲区或最大尺寸的上界检查，尤其注意有符号到无符号转换点。
- 阶段 2（PoC 生成）：根据上面分类选取对症手法——箱体类用伪造 size/extra bytes，图像类用极端尺寸或 tile 组合，字符串类用可膨胀字符（转义/UTF-8），整数混淆类用负值或大乘积，解释器类用超大 index/空输入，解码器类则调 frame/section 长度。

## 补充：按通用 OOB 模式（长度/偏移/索引/计数/脚本）重映射（复核版）
> 说明：只在公开描述能定位到触发流时列入；若案例同时具备多种手段，按主导触发点归类并在文字里提示交叉风险。

- **模式 A · Size vs Buffer 容量（Length OOB，单一长度即驱动拷贝/拼接/分配）**  
  高置信：libredwg.cve-2020-21816, libredwg.cve-2020-21814, libredwg.cve-2020-21818, libredwg.cve-2020-21819, libredwg.cve-2020-21827（字符串转义/拼接导致超长），libredwg.cve-2020-6612, libredwg.cve-2020-6614（memcpy 目标小于字段长），libredwg.cve-2020-23861（固定缓冲 memcpy），libredwg.cve-2021-42585, libredwg.cve-2021-42586（栈/堆固定块拷贝），liblouis.cve-2023-26768（字符串拼接进全局表）。  
  较高置信：libarchive.cve-2017-14503, libarchive.cve-2020-21674（归档头长度直接驱动读入固定缓冲），matio.cve-2019-20017, matio.cve-2019-20018（数据块长度直接 memcpy），readstat.cve-2018-5698（记录长度大于分配），libmodbus.cve-2022-0367（PDU 长度超出预设缓冲）。

- **模式 B · Offset + Size vs buffer_end（Offset-Plus-Size OOB，偏移累加/乘法后越界）**  
  高置信：gpac.cve-2024-0321, gpac.cve-2023-0760, gpac.cve-2023-4721, gpac.cve-2022-3178, gpac.cve-2023-3291, gpac.cve-2024-0322, gpac.cve-2023-0866, gpac.cve-2023-4682, gpac.cve-2023-48014, gpac.cve-2023-0841, gpac.cve-2023-5998, gpac.cve-2023-0819, gpac.cve-2022-29537, gpac.cve-2023-46927, gpac.cve-2024-50664, gpac.cve-2023-4754, gpac.cve-2023-4758, gpac.cve-2021-32439（箱体 size/entry size 推进指针或 memmove）；exiv2.cve-2017-17669, exiv2.cve-2020-18899, exiv2.cve-2018-17229, exiv2.cve-2018-17230, exiv2.cve-2017-17723（box length/offset 进入 DataBuf 偏移）；libplist.cve-2017-5545（长度减 header 后偏移）；libdwarf.cve-2022-32200, libdwarf.cve-2022-34299（section offset/size）；openjpeg.cve-2024-56827, openjpeg.cve-2016-10507, openjpeg.cve-2021-3575, openjpeg.cve-2017-14041（行步长/像素偏移）；openexr.cve-2020-16589, openexr.cve-2020-16587（窗口/stride）；libjpeg-turbo.cve-2020-13790（系数组偏移计算）；ImageMagick：imagemagick.cve-2018-5248, imagemagick.cve-2019-13304, imagemagick.cve-2019-13305, imagemagick.cve-2017-11533, imagemagick.cve-2019-13299, imagemagick.cve-2019-13303, imagemagick.cve-2022-1115, imagemagick.cve-2019-13295, imagemagick.cve-2017-11540, imagemagick.cve-2019-13302, imagemagick.cve-2019-13297, imagemagick.cve-2022-0284, imagemagick.cve-2019-13298, imagemagick.cve-2019-13306, imagemagick.cve-2019-13300（尺寸→偏移）。  
  较高置信：libredwg.cve-2022-45332（有符号长度减法后偏移累加）。

- **模式 C · Index vs Length（Index OOB，直接用外部索引访问数组/迭代器）**  
  高置信：njs.cve-2022-38890, njs.cve-2019-13617（JS 字符串/数组索引），mruby.cve-2022-0631, mruby.cve-2018-12248, mruby.cve-2022-0570, mruby.cve-2022-1286（VM/数组索引），php.cve-2017-12933（字符串转换索引），jq.cve-2023-50246（过滤器索引），md4c.cve-2018-11545（markdown 迭代），yara.cve-2023-40857（规则匹配索引）。

- **模式 D · Count / Entry 数 vs 分配容量（Count OOB，循环次数/条目数失配）**  
  高置信：faad2.cve-2018-20194, faad2.cve-2018-20196, faad2.cve-2021-32272, faad2.cve-2018-20361, faad2.cve-2018-20197, faad2.cve-2021-32278（band/section 计数驱动栈数组）；gpac.cve-2024-0321, gpac.cve-2023-0760, gpac.cve-2023-4721, gpac.cve-2022-3178, gpac.cve-2023-3291, gpac.cve-2024-0322, gpac.cve-2023-0866, gpac.cve-2023-4682, gpac.cve-2023-48014, gpac.cve-2023-0841, gpac.cve-2023-5998, gpac.cve-2023-0819, gpac.cve-2022-29537, gpac.cve-2023-46927, gpac.cve-2024-50664, gpac.cve-2023-4754, gpac.cve-2023-4758, gpac.cve-2021-32439（box/entry 数推进数组或乘法溢出回绕）；libdwarf.cve-2022-32200, libdwarf.cve-2022-34299（条目计数字节乘）；matio.cve-2019-20017, matio.cve-2019-20018（元素个数×大小）；libplist.cve-2017-5545（节点计数）；readstat.cve-2018-5698（行/列计数）；libmodbus.cve-2022-0367（寄存器数量）。  
  说明：Count/Entry 与 Offset/Size 经常同现，上述 gpac 既在 B 也在 D，此处强调“条目数量驱动循环/分配”的主导触发点。

- **模式 E · 脚本/文本接口越界（仍是长度/索引，但处于解释器/文本通道）**  
  高置信：njs.cve-2022-38890, njs.cve-2019-13617, mruby.cve-2022-0631, mruby.cve-2018-12248, mruby.cve-2022-0570, mruby.cve-2022-1286, php.cve-2017-12933, jq.cve-2023-50246, md4c.cve-2018-11545, yara.cve-2023-40857, gpac.cve-2024-0321（SRT 文本解析链）。
