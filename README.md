# 🔍 Spring框架漏洞扫描工具

## ✨ 功能简介
这是一款专门用于检测Spring框架常见安全漏洞的无害化扫描工具。该工具能够自动化检测多种Spring生态系统的高危漏洞。

## 🛡️ 支持的漏洞检测
本工具可以检测以下Spring框架相关漏洞：
- 🔴 CVE-2016-4977 (Spring Security OAuth2 表达式注入)
- 🔴 CVE-2017-8046 (Spring Data REST PATCH请求中的远程代码执行)
- 🔴 CVE-2018-1270 (Spring Messaging STOMP代码执行)
- 🔴 CVE-2022-22947 (Spring Cloud Gateway远程代码执行)
- 🔴 CVE-2022-22965 (Spring Core远程代码执行，又名"Spring4Shell")
- 🔴 CVE-2022-22978 (Spring认证绕过)
- 🔴 H2数据库控制台未授权访问

## 🚀 使用方法

### 💻 命令格式
```bash
python spring_vuln_scanner.py [-u URL] [-f FILE]
```

### 📝 参数说明
- `-u, --url`：指定单个目标URL进行扫描
- `-f, --file`：指定包含多个目标URL的文件路径（每行一个URL）

### 🌟 使用示例
单目标扫描：
```bash
python spring_vuln_scanner.py -u http://example.com
```

批量扫描：
```bash
python spring_vuln_scanner.py -f targets.txt
```

## 🔄 工作流程
1. 🔍 工具会对指定的目标执行一系列无害的探测请求
2. 🧪 通过分析响应内容和行为判断是否存在漏洞
3. 📊 输出扫描结果，标识检测到的漏洞

## 📋 输出说明
- `[+]` 表示目标可能存在该漏洞
- `[-]` 表示目标可能不存在该漏洞
- `[!]` 表示测试过程中出现错误

## ⚠️ 注意事项
- 本工具仅进行**无害化探测**，不执行实际的漏洞利用
- 请确保您有合法授权后再对目标系统进行扫描
- 测试结果仅供参考，可能存在误报或漏报情况
- 使用代理服务器时请注意网络延迟可能影响判断结果

## 🛑 免责声明
本工具仅供安全研究和授权测试使用。未经授权对系统进行漏洞扫描可能违反法律法规，使用者需自行承担相关法律责任。

## 🔧 技术要求
- Python 3.6+
- requests库
- argparse库

## 📜 许可证
本工具仅供学习和研究使用，严禁用于非法用途。
