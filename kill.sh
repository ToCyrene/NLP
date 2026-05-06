#!/bin/bash

MODEL_PROCESS="model_sever.py"
STREAMLIT_PROCESS="app.py"

echo "--- 正在终止 $MODEL_PROCESS 进程 ---"
pkill -f "$MODEL_PROCESS"

if [ $? -eq 0 ]; then
    echo "$MODEL_PROCESS 进程已发送终止信号。"
else
    echo " $MODEL_PROCESS 进程未找到或终止失败。"
fi

echo "---"

echo "--- 正在终止 Streamlit App (包含 $STREAMLIT_PROCESS) 进程 ---"
pkill -f "$STREAMLIT_PROCESS"

if [ $? -eq 0 ]; then
    echo " Streamlit App 进程已发送终止信号。"
else
    echo " Streamlit App 进程未找到或终止失败。"
fi