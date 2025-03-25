import requests
import json
import random
import string
import datetime
import os
import time
import logging
import shutil
import re
import uuid
from flask import Flask, request, Response, jsonify
import threading

# 配置文件路径
CONFIG_FILE = "config.json"

# 初始化配置
def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}")
        # 创建默认配置
        default_config = {
            "api_keys": {
                "same_new": "在此处填写你的反代API密钥"
            },
            "cookies": {
                "cookie_1": "在此处填写cookie"
            },
            "models": [
                {
                    "id": "claude-3-7-sonnet-20250219",
                    "name": "claude-3-7-sonnet-20250219",
                    "max_tokens": 140000
                }
            ],
            "api_url": "https://same.new/api/agent",
            "port": 8000,
            "timeout": 60,
            "debug": False,
            "default_context": "这是默认的上下文内容"
        }

        # 写入默认配置
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)

        return default_config

# 生成随机字符串的函数
def generate_random_string(length, lowercase_only=False):
    if lowercase_only:
        chars = string.ascii_lowercase + string.digits
    else:
        chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# 生成当前时间的UTC时间戳，格式为ISO 8601
def get_current_utc_timestamp():
    return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# 确保日志目录存在
def ensure_logs_dir():
    if not os.path.exists('logs'):
        os.makedirs('logs')

# 清除LOGS文件夹下的所有JSON文件
def clear_logs_folder():
    config = load_config()
    if config.get('debug', False):
        return  # 如果是调试模式，不清除文件

    try:
        for filename in os.listdir('logs'):
            if filename.endswith('.json'):
                os.remove(os.path.join('logs', filename))
    except Exception as e:
        print(f"清除logs文件夹失败: {str(e)}")

# 上传JSON文件到Same.new
def upload_json_file(file_path):
    try:
        config = load_config()
        cookie = list(config.get('cookies', {}).values())[0]  # 获取第一个cookie

        # 设置请求头
        headers = {
            "accept": "*/*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "origin": "https://same.new",
            "referer": "https://same.new/chat/test-message-lwj9gbzh15p",
            "sec-ch-ua": "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Microsoft Edge\";v=\"134\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
        }

        # 设置Cookie
        cookies = {
            "__Secure-better-auth.session_token": cookie.replace("__Secure-better-auth.session_token=", "")
        }

        # 准备文件上传
        files = {
            'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/json')
        }

        # 发送POST请求
        response = requests.post("https://same.new/api/upload", headers=headers, cookies=cookies, files=files)

        if response.status_code == 200:
            response_data = response.json()
            return response_data.get('url', '')
        else:
            print(f"上传文件失败，状态码: {response.status_code}")
            return ''
    except Exception as e:
        print(f"上传文件出错: {str(e)}")
        return ''

# 设置日志记录
def setup_logging():
    ensure_logs_dir()
    log_file = os.path.join('logs', f"proxy_{datetime.datetime.now().strftime('%Y%m%d')}.log")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('openai_proxy')

# 保存请求和响应
def save_conversation(request_data, response_data, is_error=False):
    config = load_config()
    ensure_logs_dir()

    # 创建文件名
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"conversation_{timestamp}"
    if is_error:
        filename += "_error"
    filename += ".json"

    filepath = os.path.join('logs', filename)

    # 保存数据
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            "request": request_data,
            "response": response_data
        }, f, indent=2, ensure_ascii=False)

    # 如果不是调试模式，只保留最新的一个非日志文件
    if not config.get('debug', False):
        keep_latest_conversation_file()

    return filepath

# 只保留最新的一个对话文件
def keep_latest_conversation_file():
    ensure_logs_dir()
    files = [f for f in os.listdir('logs') if f.startswith('conversation_') and f.endswith('.json')]

    if len(files) <= 1:
        return

    # 按修改时间排序
    files.sort(key=lambda x: os.path.getmtime(os.path.join('logs', x)), reverse=True)

    # 删除旧文件，保留最新的一个
    for file in files[1:]:
        try:
            os.remove(os.path.join('logs', file))
        except Exception as e:
            print(f"删除旧对话文件失败: {str(e)}")

# 清理日志文件夹，保留.log文件
def cleanup_logs_folder():
    logger = logging.getLogger('cleanup_task')

    while True:
        try:
            ensure_logs_dir()
            current_time = time.time()
            for filename in os.listdir('logs'):
                file_path = os.path.join('logs', filename)

                # 只处理非.log文件
                if not filename.endswith('.log') and os.path.isfile(file_path):
                    # 如果文件存在超过12小时，则删除
                    if current_time - os.path.getmtime(file_path) > 12 * 3600:
                        os.remove(file_path)
                        logger.info(f"已删除旧文件: {filename}")
        except Exception as e:
            logger.error(f"清理日志文件夹时出错: {str(e)}")

        # 每12小时执行一次
        time.sleep(12 * 3600)

# 解析Same.new的特殊响应格式
def parse_same_new_response(line):
    try:
        # 匹配形如 0:"文本" 的内容
        match = re.search(r'0:\"(.*?)(?<!\\)\"', line)
        if match:
            # 处理反斜杠转义
            content = match.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
            return content
    except Exception as e:
        logging.getLogger('openai_proxy').warning(f"解析响应格式出错: {str(e)}")
    return ""

# 验证API密钥
def validate_api_key(request):
    config = load_config()
    logger = logging.getLogger('openai_proxy')

    # 获取Authorization头部中的API密钥
    auth_header = request.headers.get('Authorization', '')
    api_key = ''
    if auth_header.startswith('Bearer '):
        api_key = auth_header.replace('Bearer ', '')

    # 验证API密钥
    valid_api_keys = config.get('api_keys', {}).values()
    if not valid_api_keys or not api_key or api_key not in valid_api_keys:
        logger.warning(f"API密钥验证失败: {api_key[:5]}..." if api_key else "未提供API密钥")
        error_response = {
            "error": {
                "message": "Invalid API key provided. You must provide a valid API key.",
                "type": "invalid_request_error",
                "param": None,
                "code": "invalid_api_key"
            }
        }
        return False, error_response

    return True, None

# 初始化Flask应用
app = Flask(__name__)
config = load_config()
logger = setup_logging()

# 启动日志清理线程
cleanup_thread = threading.Thread(target=cleanup_logs_folder, daemon=True)
cleanup_thread.start()

# 记录当前使用的cookie索引
current_cookie_idx = 0

# 轮询cookie
def get_next_cookie():
    global current_cookie_idx
    config = load_config()
    cookies = list(config.get('cookies', {}).values())

    if not cookies:
        return ""

    cookie = cookies[current_cookie_idx]
    current_cookie_idx = (current_cookie_idx + 1) % len(cookies)
    return cookie

# 处理流式请求
def handle_stream_request(request_data, config, headers, payload, request_id):
    """处理流式请求"""
    logger = logging.getLogger('openai_proxy')

    try:
        # 发送请求到Same.new
        response = requests.post(
            config.get('api_url', 'https://same.new/api/agent'),
            headers=headers,
            json=payload,
            timeout=config.get('timeout', 60),
            stream=True
        )

        # 检查请求是否成功
        if response.status_code != 200:
            error_msg = f"请求失败，状态码: {response.status_code}"
            logger.error(f"请求ID: {request_id} - {error_msg}")

            # 替换实际URL为API_URL
            error_text = response.text
            if config.get('api_url') in error_text:
                error_text = error_text.replace(config.get('api_url'), "API_URL")

            error_response = {
                "error": {
                    "message": f"请求API_URL失败: {error_text}",
                    "type": "api_error",
                    "param": None,
                    "code": str(response.status_code)
                }
            }

            # 保存错误信息
            save_conversation(request_data, error_response, is_error=True)

            return jsonify(error_response), response.status_code

        def generate():
            """生成流式响应"""
            full_text = ""
            try:
                logger.debug("开始接收流式响应")

                for line in response.iter_lines():
                    if line:
                        try:
                            # 直接使用latin-1解码
                            decoded_line = line.decode('latin-1')
                        except Exception as e:
                            # 如果解码失败，则跳过这行
                            logger.error(f"latin-1解码失败，跳过此行: {str(e)}")
                            continue

                        # 解析Same.new特殊格式
                        content = parse_same_new_response(decoded_line)

                        if content:
                            full_text += content
                            chunk_id = f"chatcmpl-{str(uuid.uuid4())}"

                            openai_chunk = {
                                "id": chunk_id,
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": request_data.get('model', 'gpt-3.5-turbo'),
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": content},
                                        "finish_reason": None
                                    }
                                ]
                            }

                            # 以SSE格式发送块
                            yield f"data: {json.dumps(openai_chunk)}\n\n"

                # 发送结束标记
                yield "data: [DONE]\n\n"

                # 保存完整响应到logs文件夹
                openai_response = {
                    "id": f"chatcmpl-{generate_random_string(29)}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": request_data.get('model', 'gpt-3.5-turbo'),
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": full_text
                            },
                            "finish_reason": "stop"
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 100,
                        "completion_tokens": len(full_text) // 4,
                        "total_tokens": 100 + (len(full_text) // 4)
                    }
                }
                save_conversation(request_data, openai_response)

            except Exception as e:
                error_msg = f"流式响应处理出错: {str(e)}"
                logger.error(f"请求ID: {request_id} - {error_msg}")

                error_json = json.dumps({
                    "error": {
                        "message": error_msg,
                        "type": "internal_server_error",
                        "code": "internal_server_error"
                    }
                })

                yield f"data: {error_json}\n\n"

                # 保存错误信息
                save_conversation(request_data, json.loads(error_json), is_error=True)

        # 返回流式响应
        return Response(generate(), content_type="text/event-stream")

    except Exception as e:
        error_msg = f"发送请求时出错: {str(e)}"
        logger.error(f"请求ID: {request_id} - {error_msg}")

        error_response = {
            "error": {
                "message": error_msg,
                "type": "internal_server_error",
                "param": None,
                "code": "internal_server_error"
            }
        }

        # 保存错误信息
        save_conversation(request_data, error_response, is_error=True)

        return jsonify(error_response), 500

# 处理普通请求
def handle_normal_request(request_data, config, headers, payload, request_id):
    """处理普通请求"""
    logger = logging.getLogger('openai_proxy')

    try:
        # 发送请求到Same.new
        response = requests.post(
            config.get('api_url', 'https://same.new/api/agent'),
            headers=headers,
            json=payload,
            timeout=config.get('timeout', 60),
            stream=True
        )

        # 处理响应
        if response.status_code == 200:
            logger.info(f"请求ID: {request_id} - 请求成功，状态码: {response.status_code}")

            # 获取完整响应
            full_response = ""
            parsed_content = ""

            for line in response.iter_lines():
                if line:
                    try:
                        # 直接使用latin-1解码
                        decoded_line = line.decode('latin-1')
                    except Exception as e:
                        # 如果解码失败，则跳过这行
                        logger.error(f"latin-1解码失败，跳过此行: {str(e)}")
                        continue

                    full_response += decoded_line + "\n"

                    # 尝试解析每一行的内容
                    content = parse_same_new_response(decoded_line)
                    if content:
                        parsed_content += content

            # 构建OpenAI格式的响应
            openai_response = {
                "id": f"chatcmpl-{generate_random_string(29)}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request_data.get('model', 'gpt-3.5-turbo'),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": parsed_content
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 100,  # 估计值
                    "completion_tokens": len(parsed_content) // 4,  # 估计值
                    "total_tokens": 100 + (len(parsed_content) // 4)  # 估计值
                }
            }

            # 记录原始响应和解析后的响应
            logger.debug(f"原始响应长度: {len(full_response)}")
            logger.debug(f"解析后的响应长度: {len(parsed_content)}")

            # 保存响应到logs文件夹
            save_conversation(request_data, openai_response)

            return jsonify(openai_response)
        else:
            error_msg = f"请求失败，状态码: {response.status_code}"
            logger.error(f"请求ID: {request_id} - {error_msg}")

            # 替换实际URL为API_URL
            error_text = response.text
            if config.get('api_url') in error_text:
                error_text = error_text.replace(config.get('api_url'), "API_URL")

            error_response = {
                "error": {
                    "message": f"请求API_URL失败: {error_text}",
                    "type": "api_error",
                    "param": None,
                    "code": str(response.status_code)
                }
            }

            # 保存错误信息
            save_conversation(request_data, error_response, is_error=True)

            return jsonify(error_response), response.status_code

    except Exception as e:
        error_msg = f"发送请求时出错: {str(e)}"
        logger.error(f"请求ID: {request_id} - {error_msg}")

        error_response = {
            "error": {
                "message": error_msg,
                "type": "internal_server_error",
                "param": None,
                "code": "internal_server_error"
            }
        }

        # 保存错误信息
        save_conversation(request_data, error_response, is_error=True)

        return jsonify(error_response), 500

# 处理OpenAI格式的请求并转发到Same.new
@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    start_time = time.time()
    config = load_config()
    request_data = request.json

    # 验证API密钥
    valid, error_response = validate_api_key(request)
    if not valid:
        return jsonify(error_response), 401

    # 检查是否为流式请求
    stream = request_data.get('stream', False)

    # 清除LOGS文件夹下的所有JSON文件
    clear_logs_folder()
    ensure_logs_dir()

    # 生成Same.new所需的随机ID
    chat_id = generate_random_string(11, lowercase_only=True)
    message_id = f"msg-{generate_random_string(24)}"
    request_id = generate_random_string(16)
    current_timestamp = get_current_utc_timestamp()

    # 从OpenAI格式请求中提取消息
    openai_messages = request_data.get('messages', [])
    content = ""
    if openai_messages:
        last_message = openai_messages[-1]
        content = last_message.get('content', '')

        # 添加默认上下文
        default_context = config.get('default_context', '')
        if default_context:
            content = f"{content} {default_context}"

    # 将请求数据打包为JSON文件并保存到LOGS文件夹
    json_file_path = os.path.join('logs', f"request_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(json_file_path, 'w', encoding='utf-8') as f:
        json.dump(request_data, f, indent=2, ensure_ascii=False)

    # 上传JSON文件到Same.new
    file_url = upload_json_file(json_file_path)

    # 构建Same.new请求头
    cookie = get_next_cookie()
    headers = {
        "authority": "same.new",
        "method": "POST",
        "path": "/api/agent",
        "scheme": "https",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "content-type": "application/json",
        "cookie": cookie,
        "origin": "https://same.new",
        "referer": f"https://same.new/chat/{chat_id}",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
    }

    # 构建Same.new请求负载
    payload = {
        "id": request_id,
        "messages": [
            {
                "id": message_id,
                "role": "user",
                "content": content,
                "data": {},
                "createdAt": current_timestamp,
                "parts": [
                    {
                        "type": "text",
                        "text": content
                    }
                ]
            }
        ],
        "chatId": chat_id,
        "projectId": chat_id,
        "projectName": "",
        "projectVersions": [],
        "linterOutput": "",
        "allPreviews": {},
        "terminalOutputs": {},
        "chatTotalTokensUsed": 0,
        "totalTokens": len(content),
        "recaptchaToken": "test"
    }

    # 如果成功上传文件，添加到请求负载中
    if file_url:
        payload["messages"][0]["experimental_attachments"] = [
            {
                "name": os.path.basename(json_file_path),
                "url": file_url,
                "contentType": "application/json"
            }
        ]

    logger.info(f"请求ID: {request_id} - 发送请求到 {config.get('api_url')}, stream={stream}")

    # 如果是流式请求，使用流式处理
    if stream:
        return handle_stream_request(request_data, config, headers, payload, request_id)
    else:
        return handle_normal_request(request_data, config, headers, payload, request_id)

# 获取可用模型列表
@app.route('/v1/models', methods=['GET'])
def list_models():
    config = load_config()

    # 验证API密钥
    valid, error_response = validate_api_key(request)
    if not valid:
        return jsonify(error_response), 401

    models_data = {
        "object": "list",
        "data": [{
            "id": model["id"],
            "object": "model",
            "created": int(time.time()),
            "owned_by": "organization-owner"
        } for model in config.get('models', [])]
    }
    return jsonify(models_data)

# 首页路由，显示服务状态
@app.route('/', methods=['GET'])
def index():
    # 仅在有 show_status 查询参数且有效API密钥时显示详细信息
    if request.args.get('show_status') == 'true':
        valid, error_response = validate_api_key(request)
        if not valid:
            return jsonify(error_response), 401

        return jsonify({
            "status": "running",
            "message": "OpenAI格式的Same.new反向代理服务正在运行",
            "endpoints": {
                "chat_completions": "/v1/chat/completions",
                "models": "/v1/models"
            }
        })

    # 否则只显示最基本的信息
    return jsonify({
        "status": "running",
        "message": "API服务正在运行"
    })

# 启动服务器
if __name__ == '__main__':
    # 生成默认配置
    config = load_config()

    # 确保LOGS目录存在
    ensure_logs_dir()

    logger.info("启动OpenAI格式的Same.new反向代理服务_by_XuanYuk，当前版本号：02-20250325")
    logger.info(f"服务运行在端口: {config.get('port', 5000)}")

    app.run(host='0.0.0.0', port=config.get('port', 5000), debug=config.get('debug', False))
