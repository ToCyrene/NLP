#!/bin/bash

MODEL_ENV_NAME="dc1"
STREAMLIT_ENV_NAME="ui"
PROJECT_DIR="$HOME/dc/other"
APP_PORT="7893"
CONDA_INIT_SCRIPT="$HOME/miniconda3/etc/profile.d/conda.sh" 

if [[ "$MODEL_ENV_NAME" == "your_model_env" || "$STREAMLIT_ENV_NAME" == "your_streamlit_env" ]]; then
    echo "错误：请修改脚本顶部的环境名称变量。"
    exit 1
fi

if [ ! -f "$CONDA_INIT_SCRIPT" ]; then
    echo "错误：找不到 Conda 初始化脚本：$CONDA_INIT_SCRIPT"
    exit 1
fi

cd "$PROJECT_DIR" || exit 1

COMMAND_MODEL="source $CONDA_INIT_SCRIPT && cd $PROJECT_DIR && conda activate $MODEL_ENV_NAME && python model_sever.py"
nohup bash -c "$COMMAND_MODEL" > model_server.log 2>&1 &

COMMAND_STREAMLIT="source $CONDA_INIT_SCRIPT && cd $PROJECT_DIR && conda activate $STREAMLIT_ENV_NAME && streamlit run app.py --server.port $APP_PORT"
nohup bash -c "$COMMAND_STREAMLIT" > streamlit_app.log 2>&1 &

echo "服务已在后台启动。请检查日志文件（*.log）确认成功。"