# Spring 框架漏洞检测工具 🛡️

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)

## 📝 简介

这是一款针对 Spring 框架的安全漏洞检测工具，能够检测多种常见的 Spring 安全漏洞，支持单个 URL 检测和批量检测功能。

## ✨ 功能特点

- 支持检测的漏洞:
  - CVE-2016-4977 (Spring Security OAuth2 远程代码执行)
  - CVE-2017-8046 (Spring Data REST 远程代码执行)
  - CVE-2022-22978 (Spring Security 认证绕过)
  - CVE-2022-22965 (Spring Core 远程代码执行，又称 "Spring4Shell")
  - CVE-2022-22963 (Spring Cloud Function SpEL 注入)
  - CVE-2018-1273 (Spring Data Commons 远程代码执行)
  - H2 数据库控制台未授权访问检测

- 支持单个 URL 检测和从文件批量导入目标进行检测
- 支持 DNSLog 回连验证部分漏洞

## 🔧 使用方法

### 参数说明

```
usage: demo.py -u [URL] | -f [FILE PATH] -s [SERVER ADDR]

这是spring的漏洞检测脚本

optional arguments:
  -h, --help            显示帮助信息并退出
  -u URL, --url URL     单目标URL
  -f FILE, --file FILE  批量测试文件路径
  -s SERVER, --server SERVER
                        请输入服务器地址，用于检测无回显RCE漏洞
```

### 单目标检测

```bash
python demo.py -u example.com
```

### 批量检测

```bash
python demo.py -f targets.txt
```

### HTTP外带检测

```bash
python demo.py -u example.com -s your_server_addr
```

## 🔍 检测原理

- **CVE-2016-4977**: 通过构造特殊的 OAuth 授权请求来检测表达式注入漏洞
- **CVE-2017-8046**: 利用 JSON Patch 请求中的 SpEL 表达式注入
- **CVE-2022-22978**: 尝试绕过 Spring Security 权限验证
- **CVE-2022-22965**: 检测 Spring Core 中的远程代码执行漏洞
- **CVE-2022-22963**: 测试 Spring Cloud Function 中的路由表达式注入
- **CVE-2018-1273**: 检测 Spring Data Commons 中的表单绑定漏洞
- **H2 Database**: 检测 H2 数据库控制台是否存在未授权访问问题

## 📋 输出示例

```
*[开始扫描漏洞]*
[*] 单目标扫描: example.com
[+] http://example.com - Vulnerable to CVE_2016_4977
[-] http://example.com - Not vulnerable to CVE_2017_8046
[-] http://example.com - Not vulnerable to CVE_2022_22978
[!] CVE-2022-22963：已向您的云服务器：your-dnslog.com发起请求，请关注日志结果
[-] http://example.com - Not vulnerable to CVE_2022_22965
[!] CVE-2018-1273：已向您的云服务器：your-dnslog.com发起请求，请关注日志结果
[+] http://example.com - Vulnerable to H2 Database UNACC
```

## ⚠️ 免责声明

此工具仅用于授权的安全测试和教育目的。使用此工具对未授权的系统进行测试可能违反法律法规。使用者需自行承担使用此工具的所有风险和后果。

