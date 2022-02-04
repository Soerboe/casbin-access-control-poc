from dataclasses import dataclass
from typing import List


@dataclass
class Role:
    name: str


@dataclass
class User:
    id: int
    name: str
    roles: List[Role]


@dataclass
class Patient:
    id: int
    name: str
    therapists: List[User]

    def __repr__(self):
        return f'Patient {self.name} ({self.id})'


roles: List[Role] = [
    Role('CalendarReader'),
    Role('CalendarWriter'),
    Role('Admin')
]

users: List[User] = [
    User(1, 'Sue Secretary', [r for r in roles if r.name == 'CalendarReader']),
    User(2, 'Terry Therapist', [r for r in roles if r.name in ('CalendarReader', 'CalendarWriter')]),
    User(3, 'Frank Physio', [r for r in roles if r.name in ('CalendarReader', 'CalendarWriter')]),
    User(4, 'Adam Admin', roles.copy())
]

patients: List[Patient] = [
    Patient(1, 'Perry Patient', [users[1]]),
    Patient(2, 'Sabrina Sadness', [users[1], users[2]]),
    Patient(3, 'Ned Kne', [users[2]])
]


@dataclass
class Database:
    users: List[User]
    roles: List[Role]
    patients: List[Patient]

    def find_user(self, name: str) -> User | None:
        for user in self.users:
            if user.name.startswith(name):
                return user

        return None

    def find_patient(self, name: str) -> Patient | None:
        for patient in self.patients:
            if patient.name.startswith(name):
                return patient

        return None


database = Database(users, roles, patients)
