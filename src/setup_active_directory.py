import os

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE

# Domain details from ENV variables
AD_DOMAIN_NAME = os.getenv('AD_DOMAIN_NAME', '')
AD_DOMAIN_TOP_LEVEL_SUFFIX = os.getenv('AD_DOMAIN_TOP_LEVEL_SUFFIX', 'local')
AD_DOMAIN_ADMIN_USER = os.getenv('AD_DOMAIN_ADMIN_USER', 'Administrator')
AD_DOMAIN_ADMIN_PASSWORD = os.getenv('AD_DOMAIN_ADMIN_PASSWORD', 'top-sectet-password')
DNS_DOMAIN_SUFFIX = os.getenv('DNS_DOMAIN_SUFFIX', 'dev.purestorage.com')

# AD Server details
AD_SERVER = f'ldap://{AD_DOMAIN_NAME}.{DNS_DOMAIN_SUFFIX}'
ADMIN_USER = f'{AD_DOMAIN_NAME}\\{AD_DOMAIN_ADMIN_USER}'

# Distinguished Names (DNs) - Adjust for your domain structure
BASE_DN = f'dc={AD_DOMAIN_NAME},dc={AD_DOMAIN_TOP_LEVEL_SUFFIX}'

# Connect to AD
server = Server(AD_SERVER, get_info=ALL)
conn = Connection(server, user=AD_DOMAIN_ADMIN_USER, password=AD_DOMAIN_ADMIN_PASSWORD, auto_bind=True)

def create_ad_group(_name, _gid, _description = ''):
    conn.add(f'cn={_name},ou=Groups,{BASE_DN}',
             ['top', 'group', 'groupOfNames'],
             {
                    'cn': _name,
                    'sAMAccountName': _name,
                    'description': _description,
                    'gidNumber': str(_gid)
            }
    )
    if conn.result['description'] == 'success':
        print("Group created successfully")
    else:
        print("Failed to create group:", conn.result)


def create_ad_user(_name, _uid, _description = ''):
    conn.add(f'cn={_name},ou=Users,{BASE_DN}',
             ['top', 'person', 'organizationalPerson', 'user'],
             {
                            'cn': _name,
                            'sAMAccountName': _name,
                            'userPrincipalName': _name,
                            'givenName': _name,
                            'sn': 'User',
                            'displayName': _name,
                            'mail': f'{_name}@{DNS_DOMAIN_SUFFIX}',
                            'gidNumber': str(_uid),
                            'userAccountControl': '512'
            }
    )
    if conn.result['description'] == 'success':
        print("User created successfully")
    else:
        print("Failed to create user:", conn.result)


def add_user_to_group(_group_name, _user_name, _gid):
    conn.modify(f'cn={_group_name},ou=Groups,{BASE_DN}', {
        'member': [(MODIFY_REPLACE, [f'cn={_user_name},ou=Users,{BASE_DN}'])]
    })
    if conn.result['description'] == 'success':
        print("User added to group successfully")
    else:
        print("Failed to add user to group:", conn.result)
    conn.modify(f'cn={_user_name},ou=Users,{BASE_DN}', {
        'primaryGroupID': [(MODIFY_REPLACE, [str(_gid)])]
    })
    if conn.result['description'] == 'success':
        print("Primary group set successfully")
    else:
        print("Failed to set primary group:", conn.result)

create_ad_group(_name='win_users', _gid=9060, _description='Windows Users')
create_ad_group(_name='nfs_daemons', _gid='9050', _description='NFS Daemons')

create_ad_user(_name='win_user', _uid=9060, _description = 'Windows User')
create_ad_user(_name='nfs_daemon', _uid=9050, _description = 'NFS Daemon')
add_user_to_group(_group_name='win_users', _user_name='win_user', _gid=9060)
add_user_to_group(_group_name='nfs_daemons', _user_name='nfs_daemon', _gid=9050)

# Close the connection
conn.unbind()
