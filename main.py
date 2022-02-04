from typing import List

from casbin import Enforcer
from database import database, User, Patient

rbac_enforcer = Enforcer('rbac_model.conf', 'rbac_policy.csv')
abac_enforcer = Enforcer('abac_model.conf')


def is_therapist(user_id: int, patient: Patient):
    return user_id in [f'{user.id}' for user in patient.therapists]


abac_enforcer.add_function('is_therapist', is_therapist)


def rbac_add_user_roles_to_policy(enf: Enforcer, users: List[User]):
    for user in users:
        for role in user.roles:
            enf.add_role_for_user(f'{user.id}', role.name)


rbac_add_user_roles_to_policy(rbac_enforcer, database.users)


def rbac_check_permission(user: User, obj, act):
    if rbac_enforcer.enforce(f'{user.id}', obj, act):
        print(f'{user.name} is ALLOWED {act} access to {obj}')
    else:
        print(f'{user.name} is DENIED {act} access to {obj}')


def abac_check_permission(user: User, obj):
    if abac_enforcer.enforce(f'{user.id}', obj):
        print(f'{user.name} is ALLOWED access to {obj}')
    else:
        print(f'{user.name} is DENIED access to {obj}')


if __name__ == '__main__':
    print('RBAC')
    rbac_check_permission(database.find_user('Sue'), 'calendar', 'read')
    rbac_check_permission(database.find_user('Sue'), 'calendar', 'write')

    rbac_check_permission(database.find_user('Terry'), 'calendar', 'read')
    rbac_check_permission(database.find_user('Terry'), 'calendar', 'write')

    rbac_check_permission(database.find_user('Adam'), 'calendar', 'read')
    rbac_check_permission(database.find_user('Adam'), 'calendar', 'write')

    print('ABAC')
    abac_check_permission(database.find_user('Terry'), database.find_patient('Perry'))
    abac_check_permission(database.find_user('Terry'), database.find_patient('Ned'))

