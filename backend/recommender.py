import os


def analyze_file(filename, filesize):
    ext = os.path.splitext(filename or "")[1].lower()
    size_class = "small" if int(filesize or 0) < (1024 * 1024) else "large"
    return {"extension": ext, "filesize": int(filesize or 0), "size_class": size_class}


def recommend_cipher(filename, filesize):
    info = analyze_file(filename, filesize)
    ext = info["extension"]
    size_class = info["size_class"]

    if ext == ".txt" and size_class == "small":
        return {
            "cipher": "Caesar or Vigenere",
            "reason": "Lightweight option suitable for small text files.",
        }
    if ext == ".txt" and size_class == "large":
        return {
            "cipher": "Stream Cipher",
            "reason": "Fast processing for large text content.",
        }
    if ext in (".pdf", ".docx"):
        return {
            "cipher": "AES-256",
            "reason": "Industry-standard protection for documents.",
        }
    if ext in (".jpg", ".png", ".mp4"):
        return {
            "cipher": "DES + AES",
            "reason": "Binary media benefits from block-cipher stacking.",
        }
    if ext in (".zip", ".rar"):
        return {
            "cipher": "AES-256",
            "reason": "Maximum security recommended for archives.",
        }
    return {
        "cipher": "AES-256",
        "reason": "Safe default for unknown file types.",
    }


def recommend_stack(filename, filesize):
    info = analyze_file(filename, filesize)
    ext = info["extension"]
    size_class = info["size_class"]

    if ext in (".jpg", ".png", ".mp4"):
        return {
            "stack": ["DES", "AES-256"],
            "reason": "Extra protection for binary media payloads.",
        }
    if ext == ".txt" and size_class == "small":
        return {
            "stack": ["Vigenere", "AES-256"],
            "reason": "Readable-text obfuscation with strong final encryption.",
        }
    if ext == ".txt" and size_class == "large":
        return {
            "stack": ["Stream Cipher", "AES-256"],
            "reason": "Performance first, then strong at-rest security.",
        }
    return {
        "stack": ["AES-256"],
        "reason": "Single strong cipher is sufficient for most files.",
    }
