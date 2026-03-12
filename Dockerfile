# 基于官方 Python 镜像
FROM python:3.13-slim

# 设置工作目录
WORKDIR /app

# 拷贝依赖文件
COPY requirements.txt ./

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝项目代码
COPY . .

# 启动 FastAPI 服务（假设 chart_server.py 为主入口）
CMD ["python", "chart_server.py"]
