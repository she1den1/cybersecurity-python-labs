"""Система контролю доступу (Завдання 2, Варіант 2)."""

import os
import sys

# Додаємо кореневу папку проекту до шляху для імпорту
current_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
sys.path.append(project_root)

from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанту 2
USERS = {
    "sysadmin02": {"role": "system_admin", "clearance": 4, "department": "Infrastructure", "active": True},
    "analyst234": {"role": "security_analyst", "clearance": 3, "department": "SOC", "active": True},
    "developer567": {"role": "developer", "clearance": 2, "department": "Development", "active": True},
    "intern890": {"role": "intern", "clearance": 1, "department": "HR", "active": True},
    "external123": {"role": "external", "clearance": 1, "department": "Vendor", "active": False}
}

RESOURCES = [
    ("prod_database", 4), ("dev_environment", 2), ("documentation", 1),
    ("source_code", 3), ("server_configs", 4), ("test_data", 2),
    ("compliance_docs", 3), ("system_logs", 4), ("project_files", 2),
    ("public_wiki", 1)
]

SECURITY_LEVELS = ("Open", "Internal", "Restricted", "Top Secret")

BLOCKED_USERS = {"external123", "old_account", "test_user"}


def check_access():
    """Перевіряє права доступу користувачів до ресурсів."""
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    print("--- Ресурси системи ---")
    for res_name, res_level in RESOURCES:
        # Рівні (1-4) конвертуємо в індекси (0-3) для кортежу
        level_name = SECURITY_LEVELS[res_level - 1]
        print(f"Ресурс: {res_name:<18} | Рівень безпеки: {level_name}")

    print("\n--- Перевірка прав доступу ---")
    
    # Щоб протестувати всі умови з методички, додамо до перевірки
    # існуючих користувачів, заблокованого та неіснуючого
    test_users = list(USERS.keys()) + ["old_account", "unknown_hacker"]

    for username in test_users:
        print(f"\n[{username}]")
        for res_name, res_level in RESOURCES:
            
            # 1. Якщо користувача немає в словнику
            if username not in USERS:
                print(f"user={username:<15} resource={res_name:<18} -> DENY (User not found)")
                continue

            # 2. Якщо користувач у списку заблокованих
            if username in BLOCKED_USERS:
                print(f"user={username:<15} resource={res_name:<18} -> DENY (User is blocked)")
                continue

            user_data = USERS[username]

            # 3. Якщо акаунт неактивний
            if not user_data.get("active"):
                print(f"user={username:<15} resource={res_name:<18} -> DENY (Account inactive)")
                continue

            # 4. Перевірка рівня допуску
            if user_data.get("clearance", 0) >= res_level:
                print(f"user={username:<15} resource={res_name:<18} -> ALLOW")
            else:
                print(f"user={username:<15} resource={res_name:<18} -> DENY (Insufficient clearance)")


if __name__ == "__main__":
    check_access()