"""Аналізатор надійності паролів"""

import os
import random
import sys

# shared
current_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)

from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані
PASSWORDS = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssw0rd",
    "123456",
    "SecurePass!",
    "test",
    "P@ssw0rd123",
    "welcome",
    "StrongP@ss1",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"password", "123456", "admin", "test", "welcome", "qwerty"}


def analyze_passwords():
    """Оцінює надійність паролів згідно з критеріями"""
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    # Копіюємо початковий список
    passwords_list = (
        PASSWORDS.copy()
    )  # Генеруємо 3 випадкові індекси та дублюємо паролі
    for _ in range(3):
        random_idx = random.randint(0, len(PASSWORDS) - 1)
        passwords_list.append(PASSWORDS[random_idx])

    # Вивід заголовка таблиці
    print(f"{'Пароль':<18} | {'Статус':<15}")
    print("-" * 36)

    min_len = CRITERIA["min_length"]

    for pwd in passwords_list:
        # 1. Заборонений
        if pwd.lower() in FORBIDDEN_PASSWORDS or len(pwd) < min_len:
            status = "Заборонений"
            print(f"{pwd:<18} | {status:<15}")
            continue

        # Перевірка наявності потрібних символів
        has_digit = any(char.isdigit() for char in pwd)
        has_upper = any(char.isupper() for char in pwd)
        has_special = any(not char.isalnum() for char in pwd)
        has_lower = any(char.islower() for char in pwd)

        all_met = has_digit and has_upper and has_special
        some_met = has_digit or has_upper or has_special or has_lower
        is_unique = passwords_list.count(pwd) == 1

        # Визначення статусу для валідних паролів
        if all_met and len(pwd) >= min_len + 4 and is_unique:
            status = "Дуже сильний"
        elif all_met:
            status = "Сильний"
        elif some_met:
            status = "Середній"
        else:
            status = "Слабкий"

        print(f"{pwd:<18} | {status:<15}")


if __name__ == "__main__":
    analyze_passwords()
