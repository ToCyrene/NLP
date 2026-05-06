import os
import torch
import json
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from transformers.trainer_utils import get_last_checkpoint

QWEN_BASE_PATH = "/mnt/nvme/home/zhangsh/dc/model/Qwen3"
QWEN_LORA_PATH = "/mnt/nvme/home/zhangsh/dc/model/Qwen3-LineVuln-Lora"

LLAMA_BASE_PATH = "/mnt/nvme/home/zhangsh/dc/model/llama"
LLAMA_LORA_PATH = "/mnt/nvme/home/zhangsh/dc/model/final_lora_weights_line_level"

PORT = 7899

app = FastAPI(title="Dual-Model Vulnerability Detection Server")

model_engine = {
    "qwen": {"model": None, "tokenizer": None},
    "llama": {"model": None, "tokenizer": None}
}

def get_best_lora_path(output_dir):
    if os.path.exists(os.path.join(output_dir, "adapter_model.safetensors")) or \
       os.path.exists(os.path.join(output_dir, "adapter_model.bin")):
        return output_dir
    last_ckpt = get_last_checkpoint(output_dir)
    if last_ckpt:
        return last_ckpt
    raise FileNotFoundError(f"未找到 LoRA 权重: {output_dir}")

def extract_predicted_lines(response_text):
    try:
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            json_str = response_text[start_idx : end_idx + 1]
            json_str = json_str.replace("'", '"')
            return list(set(json.loads(json_str)))
        return []
    except:
        return []

def load_single_model(base_path, lora_path, device_map_config, model_name):
    print(f"[{model_name}] 正在加载...")
    try:
        real_lora_path = get_best_lora_path(lora_path)
        
        tokenizer = AutoTokenizer.from_pretrained(base_path, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
            
        base_model = AutoModelForCausalLM.from_pretrained(
            base_path,
            device_map=device_map_config["map"],
            max_memory=device_map_config.get("max_memory", None),
            torch_dtype=torch.float16,
            trust_remote_code=True
        )
        
        model = PeftModel.from_pretrained(base_model, real_lora_path)
        model.eval()
        print(f" [{model_name}] 加载完成 (LoRA: {os.path.basename(real_lora_path)})")
        return model, tokenizer
    except Exception as e:
        print(f" [{model_name}] 加载失败: {e}")
        raise e

@app.on_event("startup")
async def load_models():
    print(" 正在初始化双模型引擎 (Qwen3 & Llama3)...")
    
    qwen_config = {
        "map": "auto", 
        "max_memory": {0: "22GiB", 1: "22GiB", 2: "0GiB"} 
    }
    q_model, q_tok = load_single_model(QWEN_BASE_PATH, QWEN_LORA_PATH, qwen_config, "Qwen3")
    model_engine["qwen"]["model"] = q_model
    model_engine["qwen"]["tokenizer"] = q_tok

    llama_config = {
        "map": {"": 2}
    }
    l_model, l_tok = load_single_model(LLAMA_BASE_PATH, LLAMA_LORA_PATH, llama_config, "Llama3")
    model_engine["llama"]["model"] = l_model
    model_engine["llama"]["tokenizer"] = l_tok

    print(" 所有模型加载完毕，服务就绪！")

class AnalysisRequest(BaseModel):
    code: str

def run_inference(model_key, prompt):
    model = model_engine[model_key]["model"]
    tokenizer = model_engine[model_key]["tokenizer"]
    device = model.device 
    
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=128,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id
        )
    
    full_output = tokenizer.decode(outputs[0], skip_special_tokens=True)
    if "### Response:" in full_output:
        return full_output.split("### Response:")[-1].strip()
    return full_output 

@app.post("/scan")
async def scan_code(req: AnalysisRequest):
    if not model_engine["qwen"]["model"] or not model_engine["llama"]["model"]:
        raise HTTPException(status_code=503, detail="Models not fully loaded")
    
    prompt = f"""### Instruction:
分析以下带有行号的代码片段，识别出所有导致安全漏洞的行。如果不存在漏洞，则输出空列表 []。

### Code Snippet (with line numbers):
{req.code}

### Response:
"""
    
    try:
        raw_qwen = run_inference("qwen", prompt)
        lines_qwen = extract_predicted_lines(raw_qwen)
    except Exception as e:
        print(f"Qwen Inference Error: {e}")
        lines_qwen = []
        raw_qwen = f"Error: {str(e)}"

    try:
        raw_llama = run_inference("llama", prompt)
        lines_llama = extract_predicted_lines(raw_llama)
    except Exception as e:
        print(f"Llama Inference Error: {e}")
        lines_llama = []
        raw_llama = f"Error: {str(e)}"

    combined_lines = list(set(lines_qwen) | set(lines_llama))
    combined_lines.sort()

    return {
        "vuln_lines": combined_lines,
        "details": {
            "qwen_lines": lines_qwen,
            "llama_lines": lines_llama,
            "qwen_raw": raw_qwen,
            "llama_raw": raw_llama
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)