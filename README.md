# pairwise-email-auth

邮件网关开启发件人校验后，SPF/DKIM/DMARC 还是能被绕：SPF 只检查 `Return-Path`，不检查 `From` 对齐；DNS 查询次数和超时没有上限，能被打成放大器；DKIM 只验 `d=` 域，不验 `i=` 身份；relaxed 和 strict 规范化混用，改一个空格就过；DMARC 只对 `p=none` 生效，拒绝策略不执行；子域继承策略没有检查；`Authentication-Results` 由客户端提供，直接采信；多段签名只验第一个；重放邮件没有时间窗；失败后仍投递到收件箱。security/email_auth.py 是核心，tests/test_email_auth.py 15个红。要修的是：From 对齐；DNS 查询上限；DKIM 身份校验；规范化一致；DMARC 策略执行；子域策略；不信任客户端结果；多签名逐个验；时间窗；失败隔离。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
