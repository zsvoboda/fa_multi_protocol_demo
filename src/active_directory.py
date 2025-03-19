import os
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, SUBTREE

class ActiveDirectory:
    """Encapsulates Active Directory operations for managing users and groups."""

    def __init__(self):
        """Initialize connection to Active Directory."""
        self.default_password = "password"  # Ensure password meets complexity

        # Domain details from ENV variables
        self.domain_name = os.getenv('AD_DOMAIN_NAME', '')
        self.domain_suffix = os.getenv('AD_DOMAIN_TOP_LEVEL_SUFFIX', 'local')
        self.admin_user = os.getenv('AD_DOMAIN_ADMIN_USER', 'Administrator')
        self.admin_password = os.getenv('AD_DOMAIN_ADMIN_PASSWORD')
        self.dns_suffix = os.getenv('DNS_DOMAIN_SUFFIX', 'dev.purestorage.com')
        self.ad_ip = os.getenv('AD_IP')

        if not self.admin_password:
            raise ValueError("AD_DOMAIN_ADMIN_PASSWORD is required but not set.")

        # AD Server details
        ad_hostname = self.ad_ip or f'{self.domain_name}.{self.dns_suffix}'
        self.ad_server = f'ldaps://{ad_hostname}'  # Ensure LDAPS is enabled
        self.admin_dn = f'{self.admin_user}@{self.domain_name}.{self.domain_suffix}'

        # Base DN
        self.base_dn = f'dc={self.domain_name},dc={self.domain_suffix}'

        # Connect to AD
        self.server = Server(self.ad_server, get_info=ALL)
        self.conn = Connection(self.server, user=self.admin_dn, password=self.admin_password, auto_bind=True)

    def ensure_ou_exists(self, ou_name):
        """Ensure an Organizational Unit exists in Active Directory."""
        ou_dn = f'OU={ou_name},{self.base_dn}'
        cn_dn = f'CN={ou_name},{self.base_dn}'

        self.conn.search(self.base_dn, f'(|(distinguishedName={ou_dn})(distinguishedName={cn_dn}))', attributes=['distinguishedName'])

        if self.conn.entries:
            print(f"'{ou_name}' already exists in Active Directory. Skipping creation.")
            return

        print(f"Creating Organizational Unit: {ou_name}")
        self.conn.add(ou_dn, 'organizationalUnit')

        if self.conn.result['description'] == 'success':
            print(f"Organizational Unit '{ou_name}' created successfully.")
        else:
            print(f"Failed to create Organizational Unit '{ou_name}':", self.conn.result)

    def create_group(self, name, gid, description=''):
        """Create an AD group if it doesn't exist."""
        group_dn = f'CN={name},OU=Groups,{self.base_dn}'

        self.conn.search(self.base_dn, f'(distinguishedName={group_dn})', attributes=['distinguishedName'])
        if self.conn.entries:
            print(f"Group '{name}' already exists. Skipping creation.")
            return

        attributes = {'cn': name, 'sAMAccountName': name, 'description': description, 'gidNumber': str(gid)}
        self.conn.add(group_dn, 'group', attributes)

        if self.conn.result['description'] == 'success':
            print(f"Group '{name}' created successfully.")
        else:
            print(f"Failed to create group '{name}':", self.conn.result)

    def create_user(self, name, uid, description=''):
        """Create an AD user and set a password separately."""
        user_dn = f'CN={name},CN=Users,{self.base_dn}'
        user_principal_name = f"{name}@{self.domain_name}.{self.domain_suffix}"

        self.conn.search(self.base_dn, f'(distinguishedName={user_dn})', attributes=['distinguishedName'])
        if self.conn.entries:
            print(f"User '{name}' already exists. Skipping creation.")
            return

        attributes = {
            'cn': name,
            'sAMAccountName': name,
            'userPrincipalName': user_principal_name,
            'givenName': name,
            'sn': 'User',
            'displayName': name,
            'mail': f'{name}@{self.dns_suffix}',
            'gidNumber': str(uid),
            'userAccountControl': 544  # Disabled User
        }

        self.conn.add(user_dn, ['top', 'person', 'organizationalPerson', 'user'], attributes)
        if self.conn.result['description'] != 'success':
            print(f"Failed to create user '{name}':", self.conn.result)
            return

        print(f"User '{name}' created successfully.")

        # Set password
        encoded_password = ('"%s"' % self.default_password).encode("utf-16-le")
        self.conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]})

        if self.conn.result['description'] != 'success':
            print(f"Failed to set password for '{name}':", self.conn.result)
            return

        print(f"Password set successfully for user '{name}'.")

        # Enable account
        self.conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
        print(f"User '{name}' enabled successfully.")

    def add_user_to_group(self, group_name, user_name):
        """Add a user to a group, ensuring both exist."""
        group_dn = f'CN={group_name},OU=Groups,{self.base_dn}'
        user_dn = f'CN={user_name},CN=Users,{self.base_dn}'

        self.conn.search(self.base_dn, f'(distinguishedName={group_dn})', attributes=['distinguishedName'])
        if not self.conn.entries:
            print(f"Group '{group_name}' not found. Skipping.")
            return

        self.conn.search(self.base_dn, f'(distinguishedName={user_dn})', attributes=['distinguishedName'])
        if not self.conn.entries:
            print(f"User '{user_name}' not found. Skipping.")
            return

        self.conn.modify(group_dn, {'member': [(MODIFY_REPLACE, [user_dn])]})
        print(f"User '{user_name}' added to group '{group_name}'.")

    def delete_object(self, dn, object_type):
        """Delete an AD object if it exists."""
        self.conn.search(self.base_dn, f'(distinguishedName={dn})', attributes=['distinguishedName'])
        if not self.conn.entries:
            print(f"{object_type} '{dn}' not found. Skipping deletion.")
            return

        self.conn.delete(dn)
        print(f"{object_type} '{dn}' deleted successfully.")

    def search_objects(self, object_class="*", search_filter="*", attributes=None):
        """Search for objects in Active Directory.

        Args:
            object_class (str): The AD object type to search (e.g., "user", "group", "*").
            search_filter (str): Custom LDAP search filter (default: "*").
            attributes (list): List of attributes to retrieve.

        Returns:
            list: A list of dictionaries containing the search results.
        """
        if attributes is None:
            attributes = ['cn', 'distinguishedName', 'sAMAccountName']

        ldap_filter = f"(&(objectClass={object_class}){search_filter})"
        self.conn.search(self.base_dn, ldap_filter, search_scope=SUBTREE, attributes=attributes)

        results = []
        for entry in self.conn.entries:
            entry_dict = {attr: entry[attr].value for attr in attributes if attr in entry}
            results.append(entry_dict)

        return results

    def close(self):
        """Close the AD connection."""
        self.conn.unbind()
        print("AD connection closed.")