import os

from flash_array import FlashArray

def setup(fa):

    # Create filesystem
    fa.create_file_system('multi_protocol_file_system')

    # Create and add NFS export policy
    fa.create_policy_nfs(name='nfs_multi_protocol_access_policy', disable_user_mapping=False)
    fa.create_policy_nfs_rule(policy_name='nfs_multi_protocol_access_policy', client='*', access='all-squash',
                              anonuid='9050', anongid='9050', nfs_version='nfsv4', security='auth_sys',
                              permission='rw')

    fa.export_managed_directory_nfs(policy_name='nfs_multi_protocol_access_policy',
                                    managed_directory_name='multi_protocol_file_system:root',
                                    export_name='multi')

    fa.create_policy_smb(name='smb_multi_protocol_access_policy')
    fa.create_policy_smb_rule(policy_name='smb_multi_protocol_access_policy', client='*')
    fa.export_managed_directory_smb(policy_name='smb_multi_protocol_access_policy',
                                    managed_directory_name='multi_protocol_file_system:root',
                                    export_name='multi')

def cleanup(fa):

    # Delete exports and policies
    fa.delete_export(export_name='multi', policy_name='nfs_multi_protocol_access_policy')
    fa.delete_export(export_name='EXCHANGE', policy_name='smb_multi_protocol_access_policy')

    # Delete file system
    fa.destroy_file_system(name='multi_protocol_file_system')
    fa.eradicate_file_system(name='multi_protocol_file_system')

    fa.delete_policy_nfs(name='nfs_multi_protocol_access_policy')
    fa.delete_policy_smb(name='smb_multi_protocol_access_policy')


# Setup connection to FlashArray
FA_HOSTNAME = os.getenv("FA_DEMO_HOSTNAME")
FA_API_TOKEN = os.getenv("FA_DEMO_API_TOKEN")

fa = FlashArray(api_token=FA_API_TOKEN, array_host=FA_HOSTNAME)
fa.authenticate()
setup(fa)
cleanup(fa)