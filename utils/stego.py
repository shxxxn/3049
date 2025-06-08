from PIL import Image
import numpy as np

def text_to_bits(text):
    return ''.join([format(ord(c), '08b') for c in text])

def bits_to_text(bits):
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def lsb_embed(image_path, message, output_path):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)
    h, w, _ = pixels.shape

    binary_msg = text_to_bits(message) + '1111111111111110'
    flat_pixels = pixels.reshape(-1, 3)

    if len(binary_msg) > len(flat_pixels):
        raise ValueError("訊息太長，圖片容納不下")

    for i in range(len(binary_msg)):
        r = flat_pixels[i][0]
        r = int(r) & 0xFE  # 清除最低位元
        r = r | int(binary_msg[i])
        flat_pixels[i][0] = np.uint8(r)

    new_pixels = flat_pixels.reshape((h, w, 3))
    Image.fromarray(new_pixels.astype('uint8')).save(output_path)

def lsb_extract(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img).reshape(-1, 3)

    bits = ""
    for p in pixels:
        bits += str(p[0] & 1)
        if bits.endswith("1111111111111110"):
            break

    clean_bits = bits[:-16]
    return bits_to_text(clean_bits)
