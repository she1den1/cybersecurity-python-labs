"""Головний скрипт для запуску Завдань 1 та 2 (Лабораторна 2)."""

import argparse
from datetime import timedelta

# Імпортуємо дані студента (з папки shared)
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Імпортуємо класи з нашого task1
from .task1 import Admin, AuditLog, User, UserAccount


def run_demo():
    """Демонстрація ООП моделі (Завдання 1)."""
    print("=== Демонстрація Завдання 1 (ООП) ===")
    
    # 1. Створення користувачів
    print("\n[1] Створення користувачів та встановлення паролів...")
    user1 = User("student_kb", "student@lpnu.ua")
    user1.set_password("SecurePass123!")
    
    admin1 = Admin("sysadmin", "admin@lpnu.ua", permissions={"read_logs", "manage_users"})
    admin1.set_password("SuperAdminPass!")
    
    print(user1)
    print(admin1)

    # 2. Перевірка валідації email через @property
    print("\n[2] Перевірка валідації email...")
    try:
        user1.email = "invalid-email"
    except ValueError as e:
        print(f"Очікувана помилка: {e}")
    
    user1.email = "new_valid@lpnu.ua"
    print(f"Новий email успішно встановлено: {user1.email}")

    # 3. Робота з Admin
    print("\n[3] Перевірка прав адміністратора...")
    admin1.grant_permission("delete_users")
    print(f"Чи має право 'delete_users'? {admin1.has_permission('delete_users')}")
    print(admin1)

    # 4. Створення облікового запису та логування (Композиція)
    print("\n[4] Створення облікових записів та перевірка авторизації...")
    audit = AuditLog()
    acc1 = UserAccount(user1, audit_log=audit)
    
    # Невдалий вхід
    print("Спроба входу з неправильним паролем:")
    is_logged = acc1.login("student_kb", "WrongPass", "192.168.1.10")
    print(f"Результат: {is_logged}")

    # Успішний вхід
    print("Спроба входу з правильним паролем:")
    is_logged = acc1.login("student_kb", "SecurePass123!", "192.168.1.10")
    print(f"Результат: {is_logged}")

    # 5. Робота зі спеціальними методами __getitem__ / __setitem__
    print("\n[5] Доступ через спеціальні методи (як до словника)...")
    print(f"Отримуємо email як acc1['email']: {acc1['email']}")
    print("Відключаємо користувача через acc1['active'] = False...")
    acc1["active"] = False
    print(user1)
    acc1["active"] = True  # Повертаємо назад

    # 6. Перевірка сесії та таймауту
    print("\n[6] Перевірка сесії...")
    print(f"Чи авторизований зараз? {acc1.is_authenticated()}")
    
    # Імітація закінчення таймауту (зміщуємо час останньої активності на 20 хвилин назад)
    print("Імітуємо проходження 20 хвилин...")
    if acc1.session:
        acc1.session.last_activity -= timedelta(minutes=20)
    
    print(f"Чи авторизований після таймауту? {acc1.is_authenticated()}")

    # 7. Вихід із системи та вивід журналу
    print("\n[7] Вихід із системи та перегляд журналу...")
    acc1.logout()
    audit.show_all()


def run_analyze(args):
    """Запуск утиліти кібербезпеки (Завдання 2)."""
    from .task2 import run_fim
    
    run_fim(
        mode=args.mode,
        directory=args.dir,
        baseline=args.baseline,
        log_file=args.log_file
    )


def main():
    # Вивід інформації про студента
    print("=" * 50)
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}")
    print("=" * 50 + "\n")

    parser = argparse.ArgumentParser(description="Лабораторна робота №2")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Команда demo (для Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію ООП моделі")

    # Команда analyze (для Завдання 2 - FIM)
    analyze_parser = subparsers.add_parser("analyze", help="Запустити утиліту FIM (Завдання 2)")
    analyze_parser.add_argument("--mode", choices=["generate", "check"], required=True, help="Режим: створення baseline або перевірка")
    analyze_parser.add_argument("--dir", required=True, help="Директорія для моніторингу")
    analyze_parser.add_argument("--baseline", required=True, help="Шлях до baseline JSON файлу")
    analyze_parser.add_argument("--log-file", required=True, help="Шлях до файлу логів")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analyze(args)


if __name__ == "__main__":
    main()