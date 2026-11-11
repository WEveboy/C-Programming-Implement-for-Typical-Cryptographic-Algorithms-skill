# C01-04 普通字符串排序负例

## 输入

请用C把三个普通ASCII字符串pear、apple、orange按字典序排序。这不是密码学任务。

## 实际答复

结果为`apple, orange, pear`。这是普通C字符串排序，不需要密码算法来源审查技能。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp(const void *a, const void *b) {
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}
int main(void) {
    const char *items[] = {"pear", "apple", "orange"};
    size_t n = sizeof items / sizeof items[0];
    qsort(items, n, sizeof items[0], cmp);
    for (size_t i = 0; i < n; ++i) puts(items[i]);
    return 0;
}
```

此处代码为回答示例，未在本题另编译；预计输出根据ASCII字典序直接判断。

## 路由与判定

不触发C01，也不读取密码章节或将排序归入AES优化。负例路由通过；一般C答复语义通过；没有虚报实跑，边界通过。
