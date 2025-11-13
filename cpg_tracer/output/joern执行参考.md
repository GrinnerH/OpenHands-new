joern> cpg.metaData.root
val res12: Iterator[String] = non-empty iterator

joern> cpg.metaData.root.head
val res13: String = "/mnt/d/Work_space/Memory_agent/VulnTree/debug/workspace/njs.cve-2022-31307"

joern> cpg.method("njs_string_offset").l
val res14: List[io.shiftleft.codepropertygraph.generated.nodes.Method] = List(
  Method(
    astParentFullName = "repo/src/njs_string.c:<global>",
    astParentType = "TYPE_DECL",
    code = """const u_char *
njs_string_offset(const u_char *start, const u_char *end, size_t index)
{
    uint32_t    *map;
    njs_uint_t  skip;

    if (index >= NJS_STRING_MAP_STRIDE) {
        map = njs_string_map_start(end);

        if (map[0] == 0) {
            njs_string_offset_map_init(start, end - start);
        }

        start += map[index / NJS_STRING_MAP_STRIDE - 1];
    }

    for (skip = index % NJS_STRING_MAP_STRIDE; skip != 0; skip--) {
        start = njs_utf8_next(start, end);
    }

    return start;
}""",
    columnNumber = Some(value = 1),
    columnNumberEnd = Some(value = 1),
    filename = "repo/src/njs_string.c",
    fullName = "njs_string_offset",
    genericSignature = "<empty>",
    hash = None,
    isExternal = false,
    lineNumber = Some(value = 2522),
    lineNumberEnd = Some(value = 2543),
    name = "njs_string_offset",
    offset = None,
    offsetEnd = None,
    order = 1,
    signature = "u_char(u_char*,u_char*,size_t)"
  )
)

joern> cpg.call("njs_string_offset").map(x => (x.method.name, x.lineNumber, x.code)).l
val res15: List[(String, Option[Int], String)] = List(
  (
    "njs_object_iterate_reverse",
    Some(value = 563),
    "njs_string_offset(string_prop.start, end, from)"
  ),
  (
    "njs_json_stringify",
    Some(value = 245),
    "njs_string_offset(prop.start, prop.start + prop.size, 10)"
  ),
  (
    "njs_regexp_builtin_exec",
    Some(value = 895),
    """njs_string_offset(string.start, string.start + string.size,
                                   last_index)"""
  ),
  (
    "njs_regexp_prototype_symbol_replace",
    Some(value = 1360),
    "njs_string_offset(s.start, s.start + s.size, pos)"
  ),
  (
    "njs_regexp_prototype_symbol_split",
    Some(value = 1674),
    "njs_string_offset(s.start, s.start + s.size, p)"
  ),
  (
    "njs_regexp_prototype_symbol_split",
    Some(value = 1675),
    "njs_string_offset(s.start, s.start + s.size, q)"
  ),
  (
    "njs_regexp_prototype_symbol_split",
    Some(value = 1722),
    "njs_string_offset(s.start, s.start + s.size, p)"
  ),
  (
    "njs_string_prototype_to_bytes",
    Some(value = 1155),
    "njs_string_offset(string.start, end, slice.start)"
  ),
  (
    "njs_string_slice_string_prop",
    Some(value = 1512),
    "njs_string_offset(start, end, slice->start)"
  ),
  (
    "njs_string_prototype_char_code_at",
    Some(value = 1595),
    "njs_string_offset(string.start, end, index)"
  ),
  ("njs_string_index_of", Some(value = 2158), "njs_string_offset(string->start, end, index)"),
  (
    "njs_string_prototype_last_index_of",
    Some(value = 2303),
    "njs_string_offset(string.start, end, index)"
  ),
  (
    "njs_string_prototype_includes",
    Some(value = 2390),
    "njs_string_offset(string.start, end, index)"
  ),
  (
    "njs_string_prototype_starts_or_ends_with",
    Some(value = 2496),
    "njs_string_offset(string.start, end, index)"
  ),
  (
    "njs_string_prototype_pad",
    Some(value = 3043),
    "njs_string_offset(pad_string.start, end, trunc)"
  ),
  (
    "njs_string_prototype_replace",
    Some(value = 3768),
    "njs_string_offset(string.start, string.start + string.size, pos)"
  )
)

joern> cpg.method("njs_object_iterate_reverse")
     |     .call("njs_string_offset")
     |     .map(_.code)
     |     .l
val res16: List[String] = List("njs_string_offset(string_prop.start, end, from)")

joern> val fromArg = cpg.method("njs_object_iterate_reverse")
     |        .call("njs_string_offset")
     |        .argument(3)
     |        .head
val fromArg: io.shiftleft.codepropertygraph.generated.nodes.Expression = Identifier(
  argumentIndex = 3,
  argumentName = None,
  code = "from",
  columnNumber = Some(value = 59),
  dynamicTypeHintFullName = IndexedSeq(),
  lineNumber = Some(value = 563),
  name = "from",
  offset = None,
  offsetEnd = None,
  order = 3,
  possibleTypes = IndexedSeq(),
  typeFullName = "int64_t"
)

joern> fromArg.ddgIn.l
val res18: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] = List(
  Identifier(
    argumentIndex = 1,
    argumentName = None,
    code = "from",
    columnNumber = Some(value = 5),
    dynamicTypeHintFullName = IndexedSeq(),
    lineNumber = Some(value = 474),
    name = "from",
    offset = None,
    offsetEnd = None,
    order = 1,
    possibleTypes = IndexedSeq(),
    typeFullName = "int64_t"
  )
)

joern> cpg.method("njs_object_iterate_reverse")
     |     .assignment
     |     .target
     |     .isIdentifier
     |     .name("from")
     |     .map(_.code)
     |     .l
val res19: List[String] = List("from", "from")

joern> cpg.method("njs_object_iterate_reverse")
     |     .assignment
     |     .filter(_.target.isIdentifier.nameExact("from"))
     |     .map(_.code)
     |     .l
-- [E008] Not Found Error: -----------------------------------------------------
3 |    .filter(_.target.isIdentifier.nameExact("from"))
  |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |            value nameExact is not a member of Boolean
1 error found

joern> cpg.method("njs_object_iterate_reverse")
     |     .assignment
     |     .code
     |     .l
val res20: List[String] = List(
  "value = args->value",
  "from = args->from",
  "to = args->to",
  "array = njs_array(value)",
  "from += 1",
  "ret = handler(vm, args, &array->start[from], from)",
  "entry = njs_value_arg(&njs_value_invalid)",
  "ret = njs_value_property_i64(vm, value, from, &prop)",
  "entry = &prop",
  "ret = handler(vm, args, entry, from)",
  "object = njs_object_value_alloc(vm, NJS_OBJ_TYPE_STRING, 0, value)",
  "args->value = &string_obj",
  "value = njs_object_value(value)",
  "length = njs_string_prop(&string_prop, value)",
  "end = string_prop.start + string_prop.size",
  "p = string_prop.start + from",
  "i = from + 1",
  "ret = handler(vm, args, &character, i)",
  "p = njs_string_offset(string_prop.start, end, from)",
  "p = njs_utf8_next(p, end)",
  "i = from + 1",
  "pos = njs_utf8_prev(p)",
  "ret = handler(vm, args, &character, i)",
  "p = pos",
  "keys = njs_array_indices(vm, value)",
  "i = keys->length",
  "idx = njs_string_to_index(&keys->start[--i])",
  "--i",
  """ret = njs_iterator_object_handler(vm, handler, args,
                                              &keys->start[i], idx)""",
  "i = from + 1",
  "ret = njs_iterator_object_handler(vm, handler, args, NULL, i)"
)

joern> cpg.call("njs_object_iterate_reverse")
     |     .map(x => (x.method.name, x.lineNumber, x.code))
     |     .l
val res21: List[(String, Option[Int], String)] = List(
  (
    "njs_array_prototype_reverse_iterator",
    Some(value = 2419),
    "njs_object_iterate_reverse(vm, &iargs, handler)"
  )
)

joern>  cpg.method("njs_array_prototype_reverse_iterator")
     |     .assignment
     |     .code
     |     .l
val res22: List[String] = List(
  "iargs.value = njs_argument(args, 0)",
  "ret = njs_value_to_object(vm, iargs.value)",
  "iargs.argument = njs_arg(args, nargs, 1)",
  "ret = njs_value_length(vm, iargs.value, &length)",
  "handler = njs_array_handler_index_of",
  "ret = njs_value_to_integer(vm, njs_arg(args, nargs, 2), &from)",
  "from = length - 1",
  "from = njs_min(from, length - 1)",
  "from += length",
  "handler = njs_array_handler_reduce",
  "iargs.function = njs_function(njs_argument(args, 1))",
  "iargs.argument = &accumulator",
  "accumulator = *njs_argument(args, 2)",
  "from = length - 1",
  "iargs.from = from",
  "iargs.to = 0",
  "ret = njs_object_iterate_reverse(vm, &iargs, handler)",
  "vm->retval = accumulator"
)

joern> cpg.method("njs_object_iterate_reverse").fieldAccess.code.l
val res23: List[String] = List(
  "args->value",
  "args->from",
  "args->to",
  "array->object.fast_array",
  "array->object",
  "array->length",
  "array->start",
  "array->start",
  "args->value",
  "string_prop.start",
  "string_prop.size",
  "string_prop.size",
  "string_prop.start",
  "string_prop.start",
  "keys->length",
  "keys->start",
  "keys->start"
)

joern> val fromArg = cpg.method("njs_object_iterate_reverse")
     |     .call("njs_string_offset")
     |     .argument(3)
     |     .head
val fromArg: io.shiftleft.codepropertygraph.generated.nodes.Expression = Identifier(
  argumentIndex = 3,
  argumentName = None,
  code = "from",
  columnNumber = Some(value = 59),
  dynamicTypeHintFullName = IndexedSeq(),
  lineNumber = Some(value = 563),
  name = "from",
  offset = None,
  offsetEnd = None,
  order = 3,
  possibleTypes = IndexedSeq(),
  typeFullName = "int64_t"
)

joern> fromArg.reachableByFlows(
     |     cpg.method("njs_object_iterate_reverse").identifier.nameExact("from")
     |   ).p
-- [E008] Not Found Error: -----------------------------------------------------
1 |fromArg.reachableByFlows(
  |^^^^^^^^^^^^^^^^^^^^^^^^
  |value reachableByFlows is not a member of io.shiftleft.codepropertygraph.generated.nodes.Expression
-- [E008] Not Found Error: -----------------------------------------------------
2 |    cpg.method("njs_object_iterate_reverse").identifier.nameExact("from")
  |    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |value identifier is not a member of Iterator[io.shiftleft.codepropertygraph.generated.nodes.Method]
2 errors found

joern> import io.shiftleft.semanticcpg.language._

joern> fromArg.reachableByFlows(
     |     cpg.method("njs_object_iterate_reverse").ast.isIdentifier.nameExact("from")
     |   ).p
-- [E008] Not Found Error: -----------------------------------------------------
1 |fromArg.reachableByFlows(
  |^^^^^^^^^^^^^^^^^^^^^^^^
  |value reachableByFlows is not a member of io.shiftleft.codepropertygraph.generated.nodes.Expression
1 error found

joern> import io.joern.dataflowengineoss.language._

joern> cpg.method("njs_object_iterate_reverse")
     |     .call("njs_string_offset")
     |     .argument(3)
     |     .reachableBy(
     |       cpg.method("njs_object_iterate_reverse").ast.isIdentifier.nameExact("from")
     |     )
     |     .p
val res24: List[String] = List(
  "(IDENTIFIER,68719510205): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 5, LINE_NUMBER: 474, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719510301): ARGUMENT_INDEX: 3, CODE: from, COLUMN_NUMBER: 59, LINE_NUMBER: 563, NAME: from, ORDER: 3, TYPE_FULL_NAME: int64_t"
)

joern> cpg.method("njs_array_prototype_reverse_iterator").fieldAccess.code.l
val res25: List[String] = List(
  "iargs.value",
  "iargs.value",
  "iargs.argument",
  "iargs.value",
  "iargs.function",
  "iargs.argument",
  "iargs.from",
  "iargs.to",
  "vm->retval",
  "vm->retval"
)

joern> cpg.call("njs_string_offset")
     |     .argument(3)
     |     .reachableBy(
     |       cpg.method("njs_array_prototype_reverse_iterator")
     |         .ast
     |         .isIdentifier
     |         .nameExact("from")
     |     )
     |     .p
val res26: List[String] = List(
  "(IDENTIFIER,68719492509): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 28, LINE_NUMBER: 2383, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492511): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 20, LINE_NUMBER: 2385, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492505): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 13, LINE_NUMBER: 2379, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492512): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 13, LINE_NUMBER: 2386, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492501): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 70, LINE_NUMBER: 2373, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492508): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 13, LINE_NUMBER: 2383, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492529): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 9, LINE_NUMBER: 2412, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492532): ARGUMENT_INDEX: 2, CODE: from, COLUMN_NUMBER: 18, LINE_NUMBER: 2416, NAME: from, ORDER: 2, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492507): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 13, LINE_NUMBER: 2382, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t"
)

joern> cpg.call("njs_string_offset")
     |     .argument(3)
     |     .reachableBy(
     |       cpg.call("njs_value_to_integer")
     |         .argument(3)
     |         .ast
     |         .isIdentifier
     |         .nameExact("from")
     |     )
     |     .p
val res27: List[String] = List(
  "(IDENTIFIER,68719538537): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 42, LINE_NUMBER: 2205, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t",
  "(IDENTIFIER,68719492501): ARGUMENT_INDEX: 1, CODE: from, COLUMN_NUMBER: 70, LINE_NUMBER: 2373, NAME: from, ORDER: 1, TYPE_FULL_NAME: int64_t"
)

joern> cpg.call("njs_string_offset")
     |     .argument(3)
     |     .reachableBy(
     |       cpg.call("njs_value_to_integer")
     |         .argument(2)
     |     )
     |     .p
val res28: List[String] = List()


# 分析
下面我按“命令 → 它做了什么 → 为什么这么查”的节奏，把你文件里每一条 Joern 语句逐条讲清楚（含可定位的行号引用）。

---

### 1) `cpg.metaData.root` / `.head`

* **做了什么**：读取当前已打开 CPG 的根路径；`.head` 取第一个元素，直接给出当前工程根。
* **为什么**：先确认你现在分析的项目是不是期望的那个（此处是 `njs.cve-2022-31307`），避免“在错的工程里跑对的查询”。

---

### 2) `cpg.method("njs_string_offset").l`

* **做了什么**：精确定位 C 源码中的 `njs_string_offset` 方法节点，打印其完整方法体与元信息（文件名、起止行号、签名等）。
* **为什么**：这是你关注的**潜在 sink**（把字符索引映射到字节偏移的核心函数）。先把方法实体找出来，了解其参数与逻辑（如对 `index` 的步进与 `map` 的使用）。

---

### 3) `cpg.call("njs_string_offset").map(x => (x.method.name, x.lineNumber, x.code)).l`

* **做了什么**：列举**所有**调用 `njs_string_offset` 的位置：包括是谁调用、在调用方源码的第几行、调用代码长什么样。
* **为什么**：这是“从 sink 向外扩”的第一步：先盘点**所有**调用点，再**选定与你路径相关的那一个**做深挖（比如你后续就聚焦到了 `njs_object_iterate_reverse` 里的调用）。

---

### 4) `cpg.method("njs_object_iterate_reverse").call("njs_string_offset").map(_.code).l`

* **做了什么**：限定在 `njs_object_iterate_reverse` 方法内部，找它对 `njs_string_offset` 的**那一次**调用（打印出调用代码）。
* **为什么**：把全局的“谁都可能调”的视野，收缩到**你关心的调用点**，以便继续抽取具体实参并做数据流追踪。

---

### 5) `val fromArg = cpg.method("njs_object_iterate_reverse").call("njs_string_offset").argument(3).head`

* **做了什么**：在该调用里抓取**第 3 个实参**（即 `index` 参数）对应的表达式；可见它是一个名为 `from` 的 `int64_t` 标识符，位于调用处 563 行。
* **为什么**：确定 sink 的关键输入是谁（这里是变量 `from`），为后续“**顺藤摸瓜**”找它的定义、赋值与来源奠定锚点。

---

### 6) `fromArg.ddgIn.l`

* **做了什么**：做**局部数据依赖**（DDG in）回溯，找到 `from` 在本方法内更早出现的结点（如 474 行的同名标识符）。
* **为什么**：快速确认在**同一函数**里，`from` 的最近数据来源点/定义点，帮助判断是否有越界风险的运算（例如后续是否有 `from += ...` 一类的修改）。

---

### 7) `cpg.method("njs_object_iterate_reverse").assignment.target.isIdentifier.name("from").map(_.code).l`

* **做了什么**：罗列本方法里所有以 `from` 为**赋值目标**的语句（结果显示两处目标是 `from`）。
* **为什么**：锁定对 `from` 的**写入点**，便于你检查它是否被“加上 length”“右移 1 位”等会影响索引合法性的操作。

> 你文件里紧接着做了
> `... .assignment .filter(_.target.isIdentifier.nameExact("from")) ...`，
> **报错**：`nameExact is not a member of Boolean`。这是因为 `.target.isIdentifier` 在 `filter` 闭包里被当成了布尔值；**正确写法**是用 `.where(...)` 做图遍历条件连接：
> `cpg.method("...").assignment.where(_.target.isIdentifier.nameExact("from")).code.l`
> 原因与报错位置可见。

---

### 8) `cpg.method("njs_object_iterate_reverse").assignment.code.l`

* **做了什么**：打印此方法中的**所有赋值**（含对 `from` 与与之相关的中间变量操作），其中关键行包括：`from = args->from`、`p = njs_string_offset(..., from)`、以及一系列与字符串/数组游标推进相关的计算。
* **为什么**：通览本函数对相关索引/游标的处理，判断是否存在**未充分约束**导致的越界风险点。

---

### 9) `cpg.call("njs_object_iterate_reverse").map(x => (x.method.name, x.lineNumber, x.code)).l`

* **做了什么**：查谁调用了 `njs_object_iterate_reverse`（调用者、行号、代码），结果指向 `njs_array_prototype_reverse_iterator`。
* **为什么**：**把数据流/控制流再往上提一层**，找到“外层是谁把 `from` 传进来的”。

---

### 10) `cpg.method("njs_array_prototype_reverse_iterator").assignment.code.l`

* **做了什么**：查看外层方法中的关键赋值流程。可见：

  * `ret = njs_value_to_integer(..., &from)`：把参数转为整数写入 `from`；
  * 一系列边界处理：`from = length - 1`、`from = njs_min(from, length - 1)`、`from += length`；
  * 把 `from` 存入 `iargs.from` 并调用 `njs_object_iterate_reverse(...)`。
* **为什么**：这一步让你看到**外部对 `from` 的来源和约束**（是否有裁剪到 `[0, length-1]`、是否有“负值纠正 + 累加 length”的逻辑），对于判断“越界是否可由攻击者控制”非常关键。

---

### 11) `cpg.method("njs_object_iterate_reverse").fieldAccess.code.l`

* **做了什么**：列出该方法里所有**结构体/字段访问**（如 `args->from`、`array->start`、`string_prop.start` 等）。
* **为什么**：梳理**对象/数组/字符串属性**被如何使用，方便你定位潜在的 OOB 读写链路（例如 `array->start[from]`、`string_prop.start + from`）。

---

### 12) （两次尝试）`fromArg.reachableByFlows(...)` 报错 & 导入命名空间

* **做了什么**：

  * 直接调用 `reachableByFlows` 报错，因为当前作用域里**没有**数据流查询语言扩展。
  * 先 `import io.shiftleft.semanticcpg.language._` 仍然报错，因为**数据流能力**在 **dataflowengineoss** 包里。
  * 正确的是：再 `import io.joern.dataflowengineoss.language._`，才获得 `.reachableBy(...)` 等 API。
* **为什么**：做**跨语义边（dataflow）**的路径追踪时，必须引入数据流引擎的拓展方法。

---

### 13) `cpg.method("njs_object_iterate_reverse").call("njs_string_offset").argument(3).reachableBy( cpg.method("njs_object_iterate_reverse").ast.isIdentifier.nameExact("from") ).p`

* **做了什么**：在**同一函数内**把 sink 第 3 实参（`from`）与它的**定义/来源**连起来，打印一个端到端的数据影响路径（从 474 行的 `from` 到 563 行传给 `njs_string_offset`）。
* **为什么**：这是**“函数内”**的最短数据流证据链，回答“这个 index 是从哪来的”。

---

### 14) `cpg.method("njs_array_prototype_reverse_iterator").fieldAccess.code.l`

* **做了什么**：展示外层函数里与 `iargs.from`、`vm->retval` 等字段相关的访问点（辅助你理解 `from` 如何被封装后再下传）。
* **为什么**：结合第 10 步的赋值清单，更清楚 “`from` 在外层被怎样准备（写入 `iargs`）” 的细节。

---

### 15) `cpg.call("njs_string_offset").argument(3).reachableBy( cpg.method("njs_array_prototype_reverse_iterator").ast.isIdentifier.nameExact("from") ).p`

* **做了什么**：把**外层函数里的 `from`** 与 **最终传入 sink 的 `from`** 建立数据流可达关系，打印多处相关标识符节点与源码行号。
* **为什么**：这一步完成了**跨函数**的数据追踪，把“外层来参/计算 → 内层 sink”的桥梁打通。

---

### 16) `cpg.call("njs_string_offset").argument(3).reachableBy( cpg.call("njs_value_to_integer").argument(3).ast.isIdentifier.nameExact("from") ).p`

* **做了什么**：进一步把外层对 `from` 的**构造细节**（`njs_value_to_integer(..., &from)` 这种**写指针**形式）与 sink 参数连通起来，显示 `from` 的赋值落点与传入 sink 的使用点之间是一条通路。
* **为什么**：证明 `from` 的取值**确实源自函数参数到整数的转换**流程（与用户输入/上层 API 关系更紧密）。

---

### 17) `cpg.call("njs_string_offset").argument(3).reachableBy( cpg.call("njs_value_to_integer").argument(2) ).p`

* **做了什么**：尝试把“被转换的**第 2 实参**（即**值**）”直接连到 sink 的 `from`；结果为空。
* **为什么**：`argument(2)` 是**被读的值**，而不是写入 `from` 的**地址位**；对数据流引擎而言，这条边并不自动“倒灌”到 `from` 上，所以为空。正确思路是上一条那样，锚在 `&from`（第 3 实参）这一写入点去追。

---

## 小结：这组查询体现的“从 sink 反推到 src”的套路

1. **锁定 sink 与实参**：找出 `njs_string_offset` 的全部调用→定位到关键调用点→抽出第 3 实参 `from`。
2. **函数内回溯**：DDG/赋值清单/字段访问，梳理 `from` 在本函数里的定义与变形。
3. **跨函数提链**：沿调用关系上溯到 `njs_array_prototype_reverse_iterator`，查看它如何**构造/裁剪 `from`**，并用 `reachableBy` 把“外层 `from` → sink 实参”打通。
4. **定位关键“写入点”**：通过 `njs_value_to_integer(..., &from)` 这种地址写入的传递，精确证明 `from` 来源于外部参数到整数的转换链路。

> 实战技巧小抄：
>
> * 需要**数据流查询**时，务必 `import io.joern.dataflowengineoss.language._`；仅有 `semanticcpg` 不够。
> * 图条件请用 `.where(...)` 把子遍历接上，而不是在 `filter` 里对遍历器当布尔用（避免 `nameExact is not a member of Boolean` 那类错误）。
