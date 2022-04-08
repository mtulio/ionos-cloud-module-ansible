import copy
from email import policy
import yaml


from ansible import __version__
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils._text import to_native
import re


HAS_SDK = True
try:
    import ionoscloud
    import ionoscloud_vm_autoscaling
except ImportError:
    HAS_SDK = False


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}

USER_AGENT = 'ansible-module/%s_ionos-cloud-sdk-python/%s' % ( __version__, ionoscloud.__version__)
VM_AUTOSCALING_USER_AGENT = 'ansible-module/%s_ionos-cloud-sdk-python/%s' % ( __version__, ionoscloud_vm_autoscaling.__version__)
DOC_DIRECTORY = 'vm-autoscaling'
STATES = ['present', 'absent', 'update']
OBJECT_NAME = 'VM Autoscaling Group'

'name'
'datacenter'
'location'

OPTIONS = {
    'target_replica_count': {
        'description': [
            'The target number of VMs in this Group. Depending on the scaling policy, this number will be adjusted automatically. '
            'VMs will be created or destroyed automatically in order to adjust the actual number of VMs to this number. If '
            'targetReplicaCount is given in the request body then it must be >= minReplicaCount and <= maxReplicaCount.',
        ],
        'available': ['present', 'update'],
        'type': 'int',
    },
    'min_replica_count': {
        'description': ['Minimum replica count value for `targetReplicaCount`. Will be enforced for both automatic and manual changes.'],
        'available': ['present', 'update'],
        'type': 'int',
    },
    'max_replica_count': {
        'description': ['Maximum replica count value for `targetReplicaCount`. Will be enforced for both automatic and manual changes.'],
        'available': ['present', 'update'],
        'type': 'int',
    },
    'replica_configuration': {
        'description': ['The replica configuration'],
        'available': ['present', 'update'],
        'type': 'dict',
    },
    'policy': {
        'description': [
            'Specifies the behavior of this autoscaling group. A policy consists of Triggers and Actions, '
            'whereby an Action is some kind of automated behavior, and the Trigger defines the circumstances, '
            'under which the Action is triggered. Currently, two separate Actions, namely Scaling In and Out are '
            'supported, triggered through the thresholds, defined for a given Metric.'
        ],
        'available': ['present', 'update'],
        'type': 'dict',
    },
    'name': {
        'description': ['The amount of storage per instance.'],
        'available': ['present', 'update'],
        'required': ['present'],
        'type': 'str',
    },
    'datacenter': {
        'description': ['VMs for this autoscaling group will be created in this virtual data center.'],
        'available': ['present'],
        'required': ['present'],
        'type': 'str',
    },
    'location': {
        'description': ['The datacenter location.'],
        'required': ['present'],
        'choices': ['us/las', 'us/ewr', 'de/fra', 'de/fkb', 'de/txl', 'gb/lhr'],
        'default': 'us/las',
        'available': ['present'],
        'type': 'str',
    },
    'vm_autoscaling_group': {
        'description': ['The ID or name of an existing VM Autoscaling Group.'],
        'available': ['update', 'absent'],
        'required': ['update', 'absent'],
        'type': 'str',
    },
    'api_url': {
        'description': ['The Ionos API base URL.'],
        'version_added': '2.4',
        'env_fallback': 'IONOS_API_URL',
        'available': STATES,
        'type': 'str',
    },
    'username': {
        # Required if no token, checked manually
        'description': ['The Ionos username. Overrides the IONOS_USERNAME environment variable.'],
        'aliases': ['subscription_user'],
        'env_fallback': 'IONOS_USERNAME',
        'available': STATES,
        'type': 'str',
    },
    'password': {
        # Required if no token, checked manually
        'description': ['The Ionos password. Overrides the IONOS_PASSWORD environment variable.'],
        'aliases': ['subscription_password'],
        'available': STATES,
        'no_log': True,
        'env_fallback': 'IONOS_PASSWORD',
        'type': 'str',
    },
    'token': {
        # If provided, then username and password no longer required
        'description': ['The Ionos token. Overrides the IONOS_TOKEN environment variable.'],
        'available': STATES,
        'no_log': True,
        'env_fallback': 'IONOS_TOKEN',
        'type': 'str',
    },
    'wait': {
        'description': ['Wait for the resource to be created before returning.'],
        'default': True,
        'available': STATES,
        'choices': [True, False],
        'type': 'bool',
    },
    'wait_timeout': {
        'description': ['How long before wait gives up, in seconds.'],
        'default': 600,
        'available': STATES,
        'type': 'int',
    },
    'state': {
        'description': ['Indicate desired state of the resource.'],
        'default': 'present',
        'choices': STATES,
        'available': STATES,
        'type': 'str',
    },
}

def transform_for_documentation(val):
    val['required'] = len(val.get('required', [])) == len(STATES) 
    del val['available']
    del val['type']
    return val

DOCUMENTATION = '''
---
module: vm_autoscaling_group
short_description: Allows operations with Ionos Cloud VM Autoscaling Groups.
description:
     - This is a module that supports creating, updating, restoring or destroying VM Autoscaling Groups
version_added: "2.0"
options:
''' + '  ' + yaml.dump(yaml.safe_load(str({k: transform_for_documentation(v) for k, v in copy.deepcopy(OPTIONS).items()})), default_flow_style=False).replace('\n', '\n  ') + '''
requirements:
    - "python >= 2.6"
    - "ionoscloud >= 6.0.2"
    - "ionoscloud-vm-autoscaling >= 1.0.0"
author:
    - "IONOS Cloud SDK Team <sdk-tooling@ionos.com>"
'''

EXAMPLE_PER_STATE = {
  'present' : '''- name: Create VM Autoscaling Group
    vm_autoscaling_group:
      postgres_version: 12
      instances: 1
      cores: 1
      ram: 2048
      storage_size: 20480
      storage_type: HDD
      location: de/fra
      connections:
        - cidr: 192.168.1.106/24
          datacenter: "{{ datacenter_response.datacenter.id }}"
          lan: "{{ lan_response1.lan.id }}"
      display_name: backuptest-04
      synchronization_mode: ASYNCHRONOUS
      db_username: test
      db_password: 7357cluster
      wait: true
    register: cluster_response
  ''',
  'update' : '''- name: Update VM Autoscaling Group
    vm_autoscaling_group:
      vm_autoscaling_group: "{{ cluster_response.vm_autoscaling_group.id }}"
      postgres_version: 12
      instances: 2
      cores: 2
      ram: 4096
      storage_size: 30480
      state: update
      wait: true
    register: updated_cluster_response
  ''',
  'absent' : '''- name: Delete VM Autoscaling Group
    vm_autoscaling_group:
      vm_autoscaling_group: "{{ cluster_response.vm_autoscaling_group.id }}"
      state: absent
  ''',
}

EXAMPLES = '\n'.join(EXAMPLE_PER_STATE.values())


def _get_resource(resource_list, identity):
    """
    Fetch and return a resource regardless of whether the name or
    UUID is passed. Returns None error otherwise.
    """

    for resource in resource_list.items:
        if identity in (resource.properties.name, resource.id):
            return resource

    return None


def _get_resource_id(resource_list, identity):
    """
    Fetch and return a resource ID regardless of whether the name or
    UUID is passed. Returns None error otherwise.
    """

    return _get_resource(resource_list, identity).id


def get_nic_object_from_dict(module, cloudapi_client, datacenter_id):
    def nic_object_from_dict(nic_dict):
        lan_id = _get_resource_id(ionoscloud.LANsApi(cloudapi_client).datacenters_lans_get(datacenter_id, depth=1), nic_dict['lan'])

        if lan_id is None:
            module.fail_json('LAN {} not found.'.format(nic_dict['lan']))
        return ionoscloud_vm_autoscaling.ReplicaNic(
            lan=lan_id,
            name=nic_dict['name'],
            dhcp=nic_dict['dhcp'],
    )
    return nic_object_from_dict


def volume_object_from_dict(volume_dict):
    return ionoscloud_vm_autoscaling.ReplicaVolumePost(
        image=volume_dict['image'],
        name=volume_dict['name'],
        size=volume_dict['size'],
        ssh_keys=volume_dict['ssh_keys'],
        type=volume_dict['type'],
        user_data=volume_dict['user_data'],
        bus=volume_dict['bus'],
        image_password=volume_dict['image_password'],
    )

def create_vm_autoscaling_group(module, vm_autoscaling_client, cloudapi_client):
    vm_autoscaling_group_server = ionoscloud_vm_autoscaling.GroupsApi(vm_autoscaling_client)
    name = module.params.get('name')

    for vm_autoscaling_group in vm_autoscaling_group_server.autoscaling_groups_get().items:
        if name == vm_autoscaling_group.properties.name:
            return {
                'changed': False,
                'failed': False,
                'action': 'create',
                'vm_autoscaling_group': vm_autoscaling_group.to_dict(),
            }

    datacenter_id = _get_resource_id(ionoscloud.DataCentersApi(cloudapi_client).datacenters_get(depth=1), module.params.get('datacenter'))

    if datacenter_id is None:
        module.fail_json('Datacenter {} not found.'.format(module.params.get('datacenter')))
    
    policy = module.params.get('policy')
    replica_configuration = module.params.get('replica_configuration')

    vm_autoscaling_group_properties = ionoscloud_vm_autoscaling.GroupProperties(
        name=module.params.get('name'),
        datacenter=module.params.get('datacenter'),
        location=module.params.get('location'),
        max_replica_count=module.params.get('max_replica_count'),
        min_replica_count=module.params.get('min_replica_count'),
        target_replica_count=module.params.get('target_replica_count'),
        policy=ionoscloud_vm_autoscaling.GroupPolicy(
            metric=policy['metric'],
            range=policy['range'],
            scale_in_action=ionoscloud_vm_autoscaling.GroupPolicyScaleInAction(
                amount=policy['scale_in_action']['amount'],
                amount_type=policy['scale_in_action']['amount_type'],
                cooldown_period=policy['scale_in_action']['cooldown_period'],
                termination_policy=policy['scale_in_action']['termination_policy'],
            ),
            scale_in_threshold=policy['scale_in_threshold'],
            scale_out_action=ionoscloud_vm_autoscaling.GroupPolicyScaleInAction(
                amount=policy['scale_out_action']['amount'],
                amount_type=policy['scale_out_action']['amount_type'],
                cooldown_period=policy['scale_out_action']['cooldown_period'],
            ),
            scale_out_threshold=policy['scale_out_threshold'],
            unit=policy['unit'],
        ),
        replica_configuration=ionoscloud_vm_autoscaling.ReplicaProperties(
            availability_zone=replica_configuration['availability_zone'],
            cores=replica_configuration['cores'],
            cpu_family=replica_configuration['cpu_family'],
            ram=replica_configuration['ram'],
            nics=list(map(get_nic_object_from_dict(module, cloudapi_client, datacenter_id), replica_configuration['nics'])),
            volumes=list(map(volume_object_from_dict, replica_configuration['volumes'])),
        ),
    )

    vm_autoscaling_group = ionoscloud_vm_autoscaling.Group(properties=vm_autoscaling_group_properties)

    try:
        vm_autoscaling_group = vm_autoscaling_group_server.autoscaling_groups_post(vm_autoscaling_group)

        return {
            'changed': True,
            'failed': False,
            'action': 'create',
            'vm_autoscaling_group': vm_autoscaling_group.to_dict(),
        }
    except Exception as e:
        module.fail_json(msg="failed to create the VM Autoscaling Group: %s" % to_native(e))
        return {
            'changed': False,
            'failed': True,
            'action': 'create',
        }


def delete_vm_autoscaling_group(module, vm_autoscaling_client):
    vm_autoscaling_group_server = ionoscloud_vm_autoscaling.GroupsApi(vm_autoscaling_client)
    vm_autoscaling_group_id = _get_resource_id(vm_autoscaling_group_server.autoscaling_groups_get(), module.params.get('vm_autoscaling_group'))
    try:
        vm_autoscaling_group_server.clusters_delete(vm_autoscaling_group_id)

        return {
            'action': 'delete',
            'changed': True,
            'id': vm_autoscaling_group_id,
        }
    except Exception as e:
        module.fail_json(msg="failed to delete the VM Autoscaling Group: %s" % to_native(e))
        return {
            'action': 'delete',
            'changed': False,
            'id': vm_autoscaling_group_id,
        }


def update_vm_autoscaling_group(module, vm_autoscaling_client, cloudapi_client):
    vm_autoscaling_group_server = ionoscloud_vm_autoscaling.GroupsApi(vm_autoscaling_client)
    vm_autoscaling_group = _get_resource(vm_autoscaling_group_server.autoscaling_groups_get(), module.params.get('vm_autoscaling_group'))

    policy = module.params.get('policy')
    replica_configuration = module.params.get('replica_configuration')

    if replica_configuration['nics'] is not None:
        nics = list(map(get_nic_object_from_dict(module, cloudapi_client, vm_autoscaling_group.datacenter), replica_configuration['nics']))
    else:
        nics = vm_autoscaling_group.replica_configuration.nics

    updated_vm_autoscaling_group_properties = ionoscloud_vm_autoscaling.GroupUpdatableProperties(
        name=module.params.get('name') or vm_autoscaling_group.name,
        datacenter=vm_autoscaling_group.datacenter,
        max_replica_count=module.params.get('max_replica_count') or vm_autoscaling_group.max_replica_count,
        min_replica_count=module.params.get('min_replica_count') or vm_autoscaling_group.min_replica_count,
        target_replica_count=module.params.get('target_replica_count') or vm_autoscaling_group.target_replica_count,
        policy=ionoscloud_vm_autoscaling.GroupPolicy(
            metric=policy['metric'] or vm_autoscaling_group.policy.metric,
            range=policy['range'] or vm_autoscaling_group.policy.range,
            scale_in_action=ionoscloud_vm_autoscaling.GroupPolicyScaleInAction(
                amount=policy['scale_in_action']['amount'] or vm_autoscaling_group.policy.scale_in_action.amount,
                amount_type=policy['scale_in_action']['amount_type'] or vm_autoscaling_group.policy.scale_in_action.amount_type,
                cooldown_period=policy['scale_in_action']['cooldown_period'] or vm_autoscaling_group.policy.scale_in_action.cooldown_period,
                termination_policy=policy['scale_in_action']['termination_policy'] or vm_autoscaling_group.policy.scale_in_action.termination_policy,
            ),
            scale_in_threshold=policy['scale_in_threshold'] or vm_autoscaling_group.policy.scale_in_threshold,
            scale_out_action=ionoscloud_vm_autoscaling.GroupPolicyScaleInAction(
                amount=policy['scale_out_action']['amount'] or vm_autoscaling_group.policy.scale_out_action.amount,
                amount_type=policy['scale_out_action']['amount_type'] or vm_autoscaling_group.policy.scale_out_action.amount_type,
                cooldown_period=policy['scale_out_action']['cooldown_period'] or vm_autoscaling_group.policy.scale_out_action.cooldown_period,
            ),
            scale_out_threshold=policy['scale_out_threshold'] or vm_autoscaling_group.policy.scale_out_threshold,
            unit=policy['unit'] or vm_autoscaling_group.policy.unit,
        ),
        replica_configuration=ionoscloud_vm_autoscaling.ReplicaProperties(
            availability_zone=replica_configuration['availability_zone'],
            cores=replica_configuration['cores'],
            cpu_family=replica_configuration['cpu_family'],
            ram=replica_configuration['ram'],
            nics=nics,
        ),
    )
    updated_vm_autoscaling_group = ionoscloud_vm_autoscaling.GroupUpdate(properties=updated_vm_autoscaling_group_properties)

    try:
        vm_autoscaling_group = vm_autoscaling_group_server.autoscaling_groups_put(
            group_id=vm_autoscaling_group.id,
            group_update=updated_vm_autoscaling_group,
        )

        return {
            'changed': True,
            'failed': False,
            'action': 'update',
            'vm_autoscaling_group': vm_autoscaling_group.to_dict(),
        }

    except Exception as e:
        module.fail_json(msg="failed to update the VM Autoscaling Group: %s" % to_native(e))
        return {
            'changed': False,
            'failed': True,
            'action': 'update',
        }


def get_module_arguments():
    arguments = {}

    for option_name, option in OPTIONS.items():
      arguments[option_name] = {
        'type': option['type'],
      }
      for key in ['choices', 'default', 'aliases', 'no_log', 'elements']:
        if option.get(key) is not None:
          arguments[option_name][key] = option.get(key)

      if option.get('env_fallback'):
        arguments[option_name]['fallback'] = (env_fallback, [option['env_fallback']])

      if len(option.get('required', [])) == len(STATES):
        arguments[option_name]['required'] = True

    return arguments


def get_sdk_config(module, sdk):
    username = module.params.get('username')
    password = module.params.get('password')
    token = module.params.get('token')
    api_url = module.params.get('api_url')

    if token is not None:
        # use the token instead of username & password
        conf = {
            'token': token
        }
    else:
        # use the username & password
        conf = {
            'username': username,
            'password': password,
        }

    if api_url is not None:
        conf['host'] = api_url
        conf['server_index'] = None

    return sdk.Configuration(**conf)


def check_required_arguments(module, state, object_name):
    # manually checking if token or username & password provided
    if (
        not module.params.get("token")
        and not (module.params.get("username") and module.params.get("password"))
    ):
        module.fail_json(
            msg='Token or username & password are required for {object_name} state {state}'.format(
                object_name=object_name,
                state=state,
            ),
        )

    for option_name, option in OPTIONS.items():
        if state in option.get('required', []) and not module.params.get(option_name):
            module.fail_json(
                msg='{option_name} parameter is required for {object_name} state {state}'.format(
                    option_name=option_name,
                    object_name=object_name,
                    state=state,
                ),
            )


def main():
    module = AnsibleModule(argument_spec=get_module_arguments(), supports_check_mode=True)

    if not HAS_SDK:
        module.fail_json(msg='both ionoscloud and ionoscloud_vm_autoscaling are required for this module, '
        'run `pip install ionoscloud ionoscloud_vm_autoscaling`')

    cloudapi_api_client = ionoscloud.ApiClient(get_sdk_config(module, ionoscloud))
    cloudapi_api_client.user_agent = USER_AGENT
    vm_autoscaling_client = ionoscloud_vm_autoscaling.ApiClient(get_sdk_config(module, ionoscloud_vm_autoscaling))
    vm_autoscaling_client.user_agent = VM_AUTOSCALING_USER_AGENT

    state = module.params.get('state')

    check_required_arguments(module, state, OBJECT_NAME)

    try:
        if state == 'present':
            module.exit_json(**create_vm_autoscaling_group(module, dbaas_client=vm_autoscaling_client, cloudapi_client=cloudapi_api_client))
        elif state == 'absent':
            module.exit_json(**delete_vm_autoscaling_group(module, vm_autoscaling_client))
        elif state == 'update':
            module.exit_json(**update_vm_autoscaling_group(module, vm_autoscaling_client, cloudapi_client=cloudapi_api_client))
    except Exception as e:
        module.fail_json(msg='failed to set {object_name} state {state}: {error}'.format(object_name=OBJECT_NAME, error=to_native(e), state=state))


if __name__ == '__main__':
    main()
