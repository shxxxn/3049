# main.py
from tkinter import filedialog, messagebox
import tkinter as tk
import os
import hashlib
from utils.stego import lsb_embed, lsb_extract
from PIL import Image

class MnemonicHiderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("加密貨幣助記詞隱寫與圖片密鑰驗證系統")
        self.master.geometry("800x600")
        self.image_path = None
        self.key_image_path = None

        self.image_label = tk.Label(master, text="尚未選擇主圖片")
        self.image_label.pack(pady=10)
        tk.Button(master, text="選擇主圖片", command=self.load_image).pack()

        self.key_image_label = tk.Label(master, text="尚未選擇密鑰圖片")
        self.key_image_label.pack(pady=10)
        tk.Button(master, text="選擇密鑰圖片", command=self.load_key_image).pack()

        self.text_label = tk.Label(master, text="輸入助記詞：")
        self.text_label.pack(pady=5)
        self.text_entry = tk.Text(master, height=5, width=60)
        self.text_entry.pack()

        tk.Button(master, text="隱藏助記詞", command=self.process_all).pack(pady=10)
        tk.Button(master, text="從圖片還原助記詞（需密鑰）", command=self.extract_mnemonic).pack(pady=10)

    def load_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.bmp")])
        if path:
            self.image_path = path
            self.image_label.config(text=f"主圖片：{os.path.basename(path)}")

    def load_key_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.bmp")])
        if path:
            self.key_image_path = path
            self.key_image_label.config(text=f"密鑰圖片：{os.path.basename(path)}")
    # 計算圖片的 SHA-256 哈希值，並取前16位作為金鑰
    def compute_image_hash(self, image_path):
        with open(image_path, 'rb') as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()[:16]  # 取前16位作為金鑰

    def process_all(self):
        if not self.image_path or not self.key_image_path:
            messagebox.showerror("錯誤", "請選擇主圖片與密鑰圖片！")
            return

        message = self.text_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("錯誤", "請輸入助記詞！")
            return

        try:
            key = self.compute_image_hash(self.key_image_path)
            final_message = f"{key}:{message}"
            output_lsb = "output_lsb.png"
            lsb_embed(self.image_path, final_message, output_lsb)
            messagebox.showinfo("成功", f"已將助記詞藏入 output_lsb.png（需指定密鑰圖片才能還原）")
        except Exception as e:
            messagebox.showerror("錯誤", str(e))

    def extract_mnemonic(self):
        if not self.image_path or not self.key_image_path:
            messagebox.showerror("錯誤", "請選擇主圖片與密鑰圖片！")
            return

        try:
            extracted = lsb_extract(self.image_path)
            expected_key = self.compute_image_hash(self.key_image_path)

            if extracted.startswith(expected_key + ":"):
                mnemonic = extracted[len(expected_key)+1:]
                messagebox.showinfo("還原成功", f"助記詞內容如下：\n{mnemonic}")
            else:
                messagebox.showerror("密鑰錯誤", "此圖片未配對對應的密鑰圖片，無法還原助記詞。")
        except Exception as e:
            messagebox.showerror("錯誤", f"無法還原助記詞：{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MnemonicHiderApp(root)
    root.mainloop()
