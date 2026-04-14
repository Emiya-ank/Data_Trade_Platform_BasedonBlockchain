# Off-ChainCommunication

一个用 Go 实现的链下文件传输原型：卖方按订单目录提供文件，买方按订单号自动拉取该目录下的全部文件。

## 项目能力

- 卖方服务端提供 HTTP 接口
- 买方客户端自动下载订单目录下全部文件
- 目录路径包含基础安全校验，防止 `..` 路径穿越
- 支持最小可运行示例数据与本地联调

## 目录结构

```text
Off-ChainCommunication/
├─ cmd/
│  ├─ buyer/main.go
│  └─ seller/main.go
├─ data/
│  └─ order-demo/
├─ downloads/
├─ src/
│  ├─ buyerclient.go
│  ├─ buyerclient_test.go
│  ├─ sellerserver.go
│  └─ sellerserver_test.go
└─ go.mod
```

## 核心流程

1. 卖方把订单文件放到 `data/<orderID>/`
2. 卖方启动服务端
3. 买方调用下载命令，先请求文件列表接口
4. 买方按列表逐个下载并保存到 `downloads/<orderID>/`

## HTTP 接口

### 1) 列出订单文件

- `GET /trade/{orderID}`
- 返回：JSON 数组，例如：

```json
["ciphertext.bin", "public.json", "proof.bin", "keyHash.json"]
```

### 2) 下载单个文件

- `GET /trade/{orderID}/{filename}`
- 文件存在则直接返回文件内容

## 快速开始

### 1) 启动卖方服务端

```powershell
go run ./cmd/seller -addr :8080 -data-dir ./data
```

### 2) 买方下载某个订单全部文件

```powershell
go run ./cmd/buyer -base-url http://localhost:8080 -order-id order-demo -save-dir ./downloads
```

## 订单文件是否固定

当前版本下，订单文件数量和文件名都不固定。  
只要文件在卖方目录 `data/<orderID>/` 下，买方就会自动下载。

注意：

- 子目录不会被下载（仅下载订单目录下的文件）
- 如果服务端返回不安全文件名（如包含路径分隔符），买方会拒绝下载

## 示例数据

示例目录：

- [data/order-demo](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/data/order-demo)

下载结果目录：

- [downloads/order-demo](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/downloads/order-demo)

## 测试与构建

```powershell
$env:GOCACHE=(Join-Path (Get-Location) '.gocache')
go test ./...
go build ./...
```

## 关键代码位置

- 卖方路由与列表接口：[sellerserver.go](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/src/sellerserver.go)
- 买方自动拉取逻辑：[buyerclient.go](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/src/buyerclient.go)
- 买方入口：[main.go](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/cmd/buyer/main.go)
- 卖方入口：[main.go](/c:/Users/Administrator/Desktop/毕业设计/ZKCPlus复现/Off-ChainCommunication/cmd/seller/main.go)
