"""Детектор цілісності файлів (Завдання 2, Варіант 2)."""

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class FileRecord:
    """Клас даних для збереження інформації про файл."""
    path: str
    sha256: str
    size: int
    modified: str


def setup_logger(log_file: str) -> logging.Logger:
    """Налаштовує логер для запису тривожних подій у файл."""
    logger = logging.getLogger("FIM_Logger")
    logger.setLevel(logging.DEBUG)
    
    # Очищуємо хендлери, щоб уникнути дублювання при повторних викликах
    if logger.hasHandlers():
        logger.handlers.clear()
        
    # Створюємо файл для логів
    fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[%(levelname)s] %(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger


def calculate_sha256(file_path: Path) -> str:
    """Обчислює SHA-256 хеш-суму файлу."""
    sha256_hash = hashlib.sha256()
    try:
        # Читаємо файл блоками, щоб не перевантажувати пам'ять великими файлами
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except OSError:
        return ""


def scan_directory(directory: Path) -> dict[str, FileRecord]:
    """Рекурсивно сканує директорію та повертає словник FileRecord."""
    records = {}
    for path in directory.rglob("*"):
        if path.is_file():
            # Ігноруємо системні файли середовища та самі логи/бази
            if any(p in path.parts for p in (".venv", "__pycache__")):
                continue
            if path.suffix == '.log' or path.name == 'baseline.json':
                continue
            
            rel_path = path.relative_to(directory).as_posix()
            file_hash = calculate_sha256(path)
            stat = path.stat()
            modified_time = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            
            records[rel_path] = FileRecord(
                path=rel_path,
                sha256=file_hash,
                size=stat.st_size,
                modified=modified_time
            )
    return records


def run_fim(mode: str, directory: str, baseline: str, log_file: str):
    """Головна функція для запуску File Integrity Monitor."""
    dir_path = Path(directory)
    baseline_path = Path(baseline)
    logger = setup_logger(log_file)
    
    if not dir_path.exists() or not dir_path.is_dir():
        print(f"[ERROR] Директорія не знайдена: {dir_path}")
        return

    if mode == "generate":
        print(f"[INFO] Scanning directory: {dir_path}")
        records = scan_directory(dir_path)
        
        # Створення папки для baseline, якщо її ще немає
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in records.values()], f, indent=4)
            
        print(f"[INFO] Baseline успішно згенеровано: {baseline_path} (Файлів: {len(records)})")
        logger.info(f"Generated new baseline at {baseline_path} with {len(records)} files.")

    elif mode == "check":
        if not baseline_path.exists():
            print(f"[ERROR] Файл baseline.json не знайдено за шляхом: {baseline_path}")
            return

        print(f"[INFO] Loading baseline file: {baseline_path}")
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
        except json.JSONDecodeError:
            print("[ERROR] Помилка читання JSON бази.")
            return
            
        baseline_records = {item["path"]: item for item in baseline_data}
        
        print(f"[INFO] Scanning directory: {dir_path}")
        current_records = scan_directory(dir_path)
        
        unchanged = 0
        modified = []
        created = []
        deleted = []
        
        # 1. Перевірка на змінені та видалені файли
        for rel_path, base_info in baseline_records.items():
            if rel_path not in current_records:
                deleted.append(rel_path)
            else:
                curr_info = current_records[rel_path]
                if curr_info.sha256 != base_info["sha256"]:
                    modified.append((rel_path, base_info["sha256"], curr_info.sha256))
                else:
                    unchanged += 1
                    
        # 2. Перевірка на новостворені файли
        for rel_path, curr_info in current_records.items():
            if rel_path not in baseline_records:
                created.append((rel_path, curr_info.size))

        total_monitored = len(baseline_records) + len(created)
        
        # Виведення результатів
        print("=== File Integrity Inspection Summary ===")
        print(f"Total monitored files : {total_monitored}")
        print(f"Unchanged files       : {unchanged}")
        print(f"Modified files        : {len(modified)}")
        print(f"Created files         : {len(created)}")
        print(f"Deleted files         : {len(deleted)}")

        # Логування та деталі аномалій
        if modified or created or deleted:
            print("=== Detected Anomalies ===")
            for m_path, old_h, new_h in modified:
                print(f"[MODIFIED] {m_path}")
                print(f"    Expected SHA-256 : {old_h}")
                print(f"    Actual SHA-256   : {new_h}")
                logger.warning(f"File MODIFIED: {m_path}")
                
            for c_path, size in created:
                print(f"[CREATED] {c_path} (Size: {size} B)")
                logger.warning(f"File CREATED: {c_path} (Size: {size})")
                
            for d_path in deleted:
                print(f"[DELETED] {d_path}")
                logger.warning(f"File DELETED: {d_path}")
                
            print(f"[WARNING] Security alerts detected! Check audit log at {log_file}")
        else:
            print("=== No Anomalies Detected ===")
            print("[INFO] Система у безпеці.")
            logger.info("Integrity check passed. No anomalies detected.")