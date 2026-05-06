import os
import json
import pandas as pd
import torch
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
)
from transformers.trainer_utils import get_last_checkpoint
from peft import LoraConfig, TaskType
from trl import SFTTrainer, SFTConfig

MODEL_PATH = "./Qwen3" 
OUTPUT_DIR = "./Qwen3-LineVuln-Lora"

TRAIN_DATA_PATH = "/mnt/nvme/home/zhangsh/dc/llm/Data/train_w_line_only.csv"
TEST_DATA_PATH = "/mnt/nvme/home/zhangsh/dc/llm/Data/test_w_line_only.csv"

MAX_SEQ_LENGTH = 2048  
BATCH_SIZE = 16         
GRADIENT_ACCUMULATION = 8 
LEARNING_RATE = 2e-4
NUM_EPOCHS = 15          

def formatting_func_line_level(example):
    code_with_lines = example.get('processed_func', '')
    line_label_str = example.get('line_label', '[]')
    
    if not code_with_lines or not line_label_str:
        return {"text": None}

    try:
        if isinstance(line_label_str, str):
            line_labels = json.loads(line_label_str)
        elif isinstance(line_label_str, list):
            line_labels = line_label_str
        else:
            line_labels = []

        vulnerable_line_numbers = [
            i + 1 for i, label in enumerate(line_labels) if label == 1
        ]
        
    except (json.JSONDecodeError, TypeError) as e:
        return {"text": None}

    prompt = f"""### Instruction:
分析以下带有行号的代码片段，识别出所有导致安全漏洞的行。如果不存在漏洞，则输出空列表 []。

### Code Snippet (with line numbers):
{code_with_lines}

### Response:
"""
    response = json.dumps(vulnerable_line_numbers)
    return {"text": prompt + response}

def load_dataset_from_csv(file_path):
    print(f"正在读取数据: {file_path} ...")
    df = pd.read_csv(file_path)
    dataset = Dataset.from_pandas(df)
    dataset = dataset.map(formatting_func_line_level)
    dataset = dataset.filter(lambda x: x["text"] is not None)
    return dataset

def main():
    print("正在加载 Tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token 
    
    print(">>> 准备训练集...")
    train_dataset = load_dataset_from_csv(TRAIN_DATA_PATH)
    
    print(">>> 准备测试/验证集...")
    eval_dataset = load_dataset_from_csv(TEST_DATA_PATH)
    
    print(f"数据准备完成。训练集: {len(train_dataset)} 条, 验证集: {len(eval_dataset)} 条")

    print("加载模型 (FP16)...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        device_map="auto",          
        torch_dtype=torch.float16,  
        trust_remote_code=True
    )
    
    print("配置 LoRA...")
    peft_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        inference_mode=False,
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    )

    print("配置训练参数...")
    args = SFTConfig(
        output_dir=OUTPUT_DIR,
        overwrite_output_dir=False,
        
        dataset_text_field="text",
        max_length=MAX_SEQ_LENGTH,
        
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION,
        learning_rate=LEARNING_RATE,
        num_train_epochs=NUM_EPOCHS,
        
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        save_total_limit=2,
        
        logging_steps=10,
        report_to="none",
        
        fp16=True,             
        optim="paged_adamw_32bit", 
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={'use_reentrant': False}
    )

    print("初始化 Trainer...")
    trainer = SFTTrainer(
        model=model,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        peft_config=peft_config,
        processing_class=tokenizer,
        args=args,
    )

    print("正在检查是否存在之前的 Checkpoint...")
    last_checkpoint = None
    if os.path.isdir(OUTPUT_DIR):
        last_checkpoint = get_last_checkpoint(OUTPUT_DIR)
    
    if last_checkpoint:
        print(f"\n>>> 检测到现有 Checkpoint: {last_checkpoint}")
        print(f">>> 将从该点继续训练，目标总 Epoch: {NUM_EPOCHS}")
        trainer.train(resume_from_checkpoint=last_checkpoint)
    else:
        print("\n>>> 未检测到 Checkpoint，开始新的训练...")
        trainer.train()

    print(f"训练完成，正在保存最佳 LoRA 权重到 {OUTPUT_DIR} ...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("保存成功！")

if __name__ == "__main__":
    main()