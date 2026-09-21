"""Головний файл для демонстрації роботи Лабораторної №1."""

# Імпортуємо головні функції з наших трьох завдань
from task1 import analyze_passwords
from task2 import check_access
from task3 import main as run_task3


def main():

    print(">>> ЗАВДАННЯ 1: Аналізатор надійності паролів")
    analyze_passwords()

    print(">>> ЗАВДАННЯ 2: Багаторівнева система контролю доступу")
    check_access()

    print(">>> ЗАВДАННЯ 3: Безпечне хешування та логування")
    run_task3()


if __name__ == "__main__":
    main()
