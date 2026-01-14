import torch
from transformers import AutoModel,AutoTokenizer

target_dir = "./local_sfr_model"

tokenizer = AutoTokenizer.from_pretrained(
    "Salesforce/SFR-Embedding-Code-400M_R",
    trust_remote_code=True,  
    torch_dtype="auto"
)

model = AutoModel.from_pretrained(
    "Salesforce/SFR-Embedding-Code-400M_R",
    trust_remote_code=True,  
    torch_dtype="auto"      
)

model.save_pretrained(target_dir)
tokenizer.save_pretrained(target_dir)
print(f"The model has been successfully saved to:{target_dir}")