"""ООП модель користувачів (Завдання 1)."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone


class User:
    """Клас базового користувача системи."""
    
    # Кількість ітерацій для PBKDF2
    HASH_ITERATIONS = 100_000

    def __init__(self, username: str, email: str, role: str = "user"):
        self.username = username
        self.role = role
        self.active = True
        self._email = ""
        self.email = email  # Викличе setter для валідації
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        """Повертає email користувача."""
        return self._email

    @email.setter
    def email(self, value: str):
        """Валідує та встановлює email через регулярний вираз."""
        # Локальна частина: починається з букви, 3-64 символи (букви, цифри, _), @, домен.
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        """Безпечно хешує пароль за допомогою PBKDF2 та солі."""
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            self.HASH_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє правильність пароля, стійко до timing attacks."""
        if not self.__password_salt or not self.__password_hash:
            return False
            
        test_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            self.HASH_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        """Деактивує обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"[{self.role}] {self.username} ({self.email}) - {status}"


class Admin(User):
    """Клас адміністратора, що успадковує User (Is-A)."""

    def __init__(self, username: str, email: str, permissions: set | None = None):
        super().__init__(username, email, role="admin")
        # Уникаємо використання змінних колекцій як дефолтних аргументів
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(self.permissions) if self.permissions else "None"
        return f"{base_str} | Permissions: [{perms}]"


class Session:
    """Клас для відстеження активної сесії користувача."""

    def __init__(self, ip: str):
        self.ip = ip
        # Використовуємо UTC для уникнення проблем з локальними часовими поясами
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        """Оновлює час останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут сесії."""
        if timeout_sec <= 0:
            return False
        delta = datetime.now(timezone.utc) - self.last_activity
        return delta.total_seconds() < timeout_sec


@dataclass
class LogRecord:
    """Клас даних (DataClass) для зручного зберігання одного запису логу."""
    time: datetime
    user: str
    action: str


class AuditLog:
    """Журнал аудиту для фіксації подій входу/виходу."""

    def __init__(self):
        self.records = []

    def add_log(self, username: str, action: str):
        record = LogRecord(
            time=datetime.now(timezone.utc),
            user=username,
            action=action
        )
        self.records.append(record)

    def show_all(self):
        print("\n--- Журнал Аудиту ---")
        for r in self.records:
            time_str = r.time.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{time_str}] {r.user} -> {r.action}")


class UserAccount:
    """
    Головний клас управління обліковим записом.
    Демонструє композицію (Has-A): містить у собі User, Session та AuditLog.
    """

    SESSION_TIMEOUT_SEC = 900  # 15 хвилин

    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.audit_log = audit_log if audit_log else AuditLog()
        self.session = None

    def login(self, username: str, password: str, ip: str) -> bool:
        """Спроба авторизації з фіксацією в логах."""
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        """Перевіряє, чи авторизований користувач в даний момент."""
        return bool(self.session and self.session.is_active(self.SESSION_TIMEOUT_SEC))

    def logout(self):
        """Завершує сесію користувача."""
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        """Дозволяє отримувати властивості як зі словника account['email']."""
        if hasattr(self.user, key) and key not in ("_User__password_hash", "_User__password_salt"):
            return getattr(self.user, key)
        raise KeyError(f"Невідомий або заборонений атрибут: {key}")

    def __setitem__(self, key: str, value):
        """Дозволяє змінювати властивості як у словнику account['active'] = False."""
        if key in ("username", "email", "role", "active"):
            if key == "active" and not isinstance(value, bool):
                raise TypeError("Атрибут active має бути логічного типу (bool)")
            setattr(self.user, key, value)
        else:
            raise KeyError(f"Не можна змінити атрибут: {key}")