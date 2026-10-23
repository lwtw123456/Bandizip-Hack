# Bandizip-Hack
逆向练习，实现了 Bandizip 专业版的授权绕过，实测 v7.47。顺便还屏蔽了版本更新。

正常来说，patch 授权校验函数是最简单的做法，但是此次练习网络栈 hook，给自己加了点难度。

主要工作量在分析透彻 Bandizip 的联网授权加密协议。

邮箱随便填，但是必须有 **@** 且不能在首位。

密钥随便填，但是必须以 **20** 开头，10-12位必须为 **PRO**，总长度必须为 **38**。

最简示例 `200000000PRO00000000000000000000000000`。

## Credits

DLL Proxy 部分基于 **AheadLibEx**：

```text
https://github.com/i1tao/AheadLibEx
```

Author: i1tao

## Disclaimer

本项目仅用于 **逆向工程技术研究与学习交流**。

## License

MIT License
