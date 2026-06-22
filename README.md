# netpeek
Peek at the HTTP/S requests made by any command — no system proxy changes, no GUI required.

## 背景
日常工作中有一些 cli 程序，有一些命令会发起请求，如 update 这种，这个脚本可以快速分析某 cli 程序的某些命令会发起哪些 http 请求，默认 Macos 使用，Linux下看 https 可自行安装证书


## 安装依赖

pip install mitmproxy


## 首次运行——信任 CA 证书

Go 编译的程序（以及部分其他运行时）使用系统 Keychain 验证证书，而非读取环境变量。如需抓取此类程序的流量，执行一次以下命令：

sudo security add-trusted-cert \
  -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.mitmproxy/mitmproxy-ca-cert.pem

抓包完成后建议移除：

sudo security delete-certificate \
  -c "mitmproxy" \
  /Library/Keychains/System.keychain

## 用法

python netpeek.py '<命令>'

参数：
  -v, --verbose   打印请求/响应头和 body
  -o FILE         将结果保存为 JSON 文件

## 示例

python netpeek.py 'curl https://httpbin.org/get' <br>

python netpeek.py -v 'wget -q -O- https://example.com' <br>

python netpeek.py -o result.json 'python3 my_script.py' <br>

python netpeek.py '/Applications/MyApp.app/Contents/MacOS/MyApp --update'

## 注意事项

- curl、wget、Python requests、Node.js fetch 等常见工具开箱即用
- Go / Java 编译的程序需要完成上方的系统 CA 信任步骤
- 忽略代理环境变量的程序（部分 Electron / 原生 Swift 应用）可能无法被捕获
