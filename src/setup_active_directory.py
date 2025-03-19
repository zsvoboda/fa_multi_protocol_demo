import socket
import socks

from active_directory import ActiveDirectory

if __name__ == "__main__":
    # Setup SOCKS5 proxy
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, 'localhost', 1080)
    socket.socket = socks.socksocket

    ad = ActiveDirectory()

    # Ensure Organizational Units exist
    ad.ensure_ou_exists("Groups")
    ad.ensure_ou_exists("Users")

    # Delete existing users & groups
    ad.delete_object(f'CN=win_user,CN=Users,{ad.base_dn}', 'User')
    ad.delete_object(f'CN=nfs_daemon,CN=Users,{ad.base_dn}', 'User')
    ad.delete_object(f'CN=win_users,OU=Groups,{ad.base_dn}', 'Group')
    ad.delete_object(f'CN=nfs_daemons,OU=Groups,{ad.base_dn}', 'Group')

    # Create groups
    ad.create_group('win_users', 9060, 'Windows Users')
    ad.create_group('nfs_daemons', 9050, 'NFS Daemons')

    # Create users
    ad.create_user('win_user', 9060, 'Windows User')
    ad.create_user('nfs_daemon', 9050, 'NFS Daemon')

    # Assign users to groups
    ad.add_user_to_group('win_users', 'win_user')
    ad.add_user_to_group('nfs_daemons', 'nfs_daemon')

    # Search for a specific user
    specific_user = ad.search_objects(object_class="user", search_filter="(cn=win_user)",
                                      attributes=["cn", "sAMAccountName", "mail", "gidNumber", "PrimaryGroupID"])
    print("Specific User:", specific_user)

    # Close the connection
    ad.close()