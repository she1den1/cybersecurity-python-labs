"""Безпечне хешування, CSV-база та JSON-логування (Завдання 3, Варіант 2)."""

import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

current_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)

from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Константи
MIN_PASSWORD_LENGTH = 10
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"  # Для 2 варіанту це "00002"
DATA_DIR = os.path.join(current_dir, "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Власний клас винятку для помилок валідації пароля."""


def log_event(func):
    """Декоратор для логування спроб входу у файл JSON."""

    @wraps(func)
    def wrapper(username, password, *args, **kwargs):
        result = "failure"
        try:
            is_success = func(username, password, *args, **kwargs)
            if is_success:
                result = "success"
            return is_success
        except Exception as e:
            result = f"failure ({type(e).__name__})"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": args,
                "kwargs": kwargs,
            }

            os.makedirs(DATA_DIR, exist_ok=True)

            logs = []
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            logs.append(log_entry)

            try:
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except OSError as e:
                print(f"Помилка запису логів: {e}")

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує sha3_224 хеш від пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль надто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    salted_password = password + salt
    return hashlib.sha3_224(salted_password.encode("utf-8")).hexdigest()


def create_user(username, password):
    """Створює кортеж (логін, хеш)."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users(users_list):
    """Створює CSV базу користувачів."""
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            for username, password in users_list:
                try:
                    user_record = create_user(username, password)
                    writer.writerow(user_record)
                except (ValueError, ValidationError) as e:
                    print(f"Пропущено користувача {username}: {e}")
        print(f"База даних успішно створена: {USERS_CSV_PATH}")
    except PermissionError:
        print("Помилка: Немає прав на запис файлу бази даних.")
    except OSError as e:
        print(f"Помилка вводу/виводу: {e}")


@log_event
def login(username: str, password: str) -> bool:
    """Автентифікує користувача за базою CSV."""
    if not username or not password:
        raise ValueError("Логін або пароль порожні.")

    try:
        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            users_db = list(reader)

        try:
            login_hash = generate_hash(password, PERSONAL_SALT)
        except ValidationError:
            return False

        for user in users_db:
            if user["username"] == username and user["password_hash"] == login_hash:
                return True
        return False

    except FileNotFoundError:
        print("Помилка: База даних користувачів не знайдена.")
        raise
    except (OSError, PermissionError) as e:
        print(f"Помилка читання бази: {e}")
        raise


def read_users():
    """Читає вміст CSV-файлу та виводить його на екран у вигляді таблиці."""
    print("\n--- Читання бази даних ---")
    try:
        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                print(f"{row[0]:<15} | {row[1]}")
    except FileNotFoundError:
        print("Помилка: База даних користувачів не знайдена.")
        raise
    except (OSError, PermissionError) as e:
        print(f"Помилка читання бази: {e}")
        raise


def main():
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    # Кортеж із 10 користувачів
    users_to_register = (
        ("devops_lead", "Pipeline2026@secure"),
        ("admin_usr", "SuperSecret123!"),
        ("user01", "Short1!"),  # ValidationError (менше 10 символів)
        ("guest", ""),  # ValueError
        ("analyst", "AnalyzeThis#2024"),
        ("manager", "ManagerPass!99"),
        ("tester", "TestTestTest!"),
        ("intern", "InternPass!123"),
        ("hacker", "HackThePlanet1"),
        ("ceo_boss", "BigBossPassword!"),
    )

    print("--- Реєстрація користувачів ---")
    create_users(users_to_register)

    # Викликаємо нову функцію для читання БД
    read_users()

    print("\n--- Перевірка авторизації ---")
    test_logins = [
        ("devops_lead", "Pipeline2026@secure"),  # Успішний вхід
        ("analyst", "WrongPassword!"),  # Неправильний пароль
        ("unknown", "SomePass123!"),  # Неіснуючий юзер
        ("", "Pass!12345"),  # Помилка ValueError
    ]

    for user, pwd in test_logins:
        success = login(user, pwd)
        status = "УСПІХ" if success else "ВІДМОВА"
        print(f"Вхід для {user:<12}: {status}")


if __name__ == "__main__":
    main()
