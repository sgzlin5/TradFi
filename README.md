# TradFi

Gate.io TradFi 交易工具 - K线图表可视化与持仓管理

## 功能特性

- **K线图表**：支持多周期 K 线展示（1m/5m/15m/30m/1h/4h/1d）
- **技术指标**：支持 MA（移动平均线）、BB（布林带）、MACD 指标
- **账户管理**：查看账户余额、保证金、MT5 账户信息
- **持仓管理**：实时查看持仓、支持修改止盈止损、一键平仓
- **收益统计**：今日/昨日已实现盈亏统计
- **数据安全**：API 密钥加密存储，安全登录

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 API 密钥

创建 `config.json` 文件（请替换为你的 Gate.io API 密钥）：

```json
{
  "GATE_API_KEY": "your_api_key",
  "GATE_API_SECRET": "your_api_secret"
}
```

然后运行加密脚本生成 `config.enc`：

```bash
python encrpty.py
# 按提示输入加密密码
```

### 3. 启动服务

```bash
python chart_server.py
```

访问 http://localhost:23333 ，输入密码登录即可使用。

## 项目结构

```
tradfi/
├── chart_server.py     # FastAPI 后端服务
├── demo.py             # API 调用示例
├── config.enc          # 加密的配置文件
├── encrpty.py         # 配置加密工具
├── config_load.py     # 配置加载工具
├── templates/
│   ├── index.html     # K线图表前端页面
│   └── login.html    # 登录页面
└── README.md
```

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/klines` | GET | 获取 K 线数据 |
| `/api/assets` | GET | 获取账户资产 |
| `/api/mt5account` | GET | 获取 MT5 账户信息 |
| `/api/positions` | GET | 获取持仓列表 |
| `/api/positions/{id}` | PUT | 修改止盈止损 |
| `/api/positions/{id}/close` | POST | 平仓 |
| `/api/pnl_summary` | GET | 收益汇总 |

## 技术栈

- **后端**：FastAPI + uvicorn
- **前端**：Lightweight Charts
- **加密**：cryptography (Fernet + PBKDF2)
- **API**：Gate.io TradFi REST API
