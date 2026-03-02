#!/usr/bin/env python3

import datetime
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import threading
import pynetbox
from pynetbox.core.response import Record
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import urllib3
import ssl
from deepdiff import DeepDiff
import re
import logging
import hashlib
import ipaddress
import requests
import time
from urllib.parse import urljoin

object_cache={}
cache_lock = threading.Lock()
regex_cache = {}
regex_cache_lock = threading.Lock()
perf_stats = {}
perf_lock = threading.Lock()
CACHE_LOG_EVERY = 1000

PROTECTED_FIELDS = ['description', 'role']

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] [%(levelname)s] [%(funcName)s] %(message)s',
    handlers=[
        logging.FileHandler("data_transfer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def perf_increment(metric_name, count=1):
    with perf_lock:
        perf_stats[metric_name] = perf_stats.get(metric_name, 0) + count


def perf_add_time(metric_name, duration_seconds):
    with perf_lock:
        perf_stats[metric_name] = perf_stats.get(metric_name, 0.0) + duration_seconds


def log_performance_summary():
    with perf_lock:
        stats_snapshot = dict(perf_stats)

    if not stats_snapshot:
        logger.info("PERF: No performance metrics collected")
        return

    logger.info("PERF SUMMARY (create_or_update):")

    for metric in sorted(stats_snapshot.keys()):
        value = stats_snapshot[metric]
        if metric.endswith(".time"):
            logger.info(f"PERF {metric}={value:.3f}s")
        else:
            logger.info(f"PERF {metric}={value}")


def log_cache_hit_miss_periodic(object_type):
    with perf_lock:
        hits = perf_stats.get(f"{object_type}.cache.hit", 0)
        misses = perf_stats.get(f"{object_type}.cache.miss", 0)

    total = hits + misses
    if total > 0 and total % CACHE_LOG_EVERY == 0:
        hit_rate = (hits / total) * 100
        logger.info(
            f"CACHE {object_type}: hits={hits} misses={misses} total={total} hit_rate={hit_rate:.1f}%"
        )


def get_env_int(name, default, min_value=1):
    raw_value = os.environ.get(name)
    source = "env"

    if raw_value is None or str(raw_value).strip() == "":
        value = default
        source = "default"
    else:
        try:
            value = int(str(raw_value).strip())
        except (TypeError, ValueError):
            logger.warning(f"Invalid {name} value '{raw_value}'; defaulting to {default}")
            value = default
            source = "default"

    if value < min_value:
        logger.warning(f"{name} must be >= {min_value}; defaulting to {min_value}")
        value = min_value
        source = "default"

    logger.info(f"Config {name}={value} (source={source})")
    return value


def start_background_precache(netbox_url, netbox_token):
    def _precache_worker():
        try:
            cache_nb = pynetbox.api(netbox_url, token=netbox_token)
            cache_nb.http_session.verify = False
            cache_nb.http_session.headers.update({"User-Agent": "netbox-vcenter-sync/0.0.1"})
            pre_cache_objects(cache_nb)
            logger.info("Background pre-cache completed")
        except Exception as e:
            logger.error(f"Background pre-cache failed: {e}")
            logger.error("Traceback details:")
            logger.error(traceback.format_exc())

    thread = threading.Thread(target=_precache_worker, name="PreCache", daemon=True)
    thread.start()
    return thread

ssl_context = ssl._create_unverified_context()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RelativeSession(requests.Session):
    def __init__(self, base_url):
        super(RelativeSession, self).__init__()
        self.__base_url = base_url

    def request(self, method, url, **kwargs):
        url = urljoin(self.__base_url, url)
        return super(RelativeSession, self).request(method, url, **kwargs)

def pre_cache_objects(nb):
    logger.info("Starting pre-caching of NetBox objects.")
    overall_start = time.perf_counter()
    total_cached = 0

    objects_to_cache = {
        "virtualmachine": {
            "fetch_function": nb.virtualization.virtual_machines.all,
            "object_type": "virtualization.virtual_machines",
            "key_fields": ["name", "cluster"],
        },
        "device": {
            "fetch_function": nb.dcim.devices.all,
            "object_type": "dcim.devices",
            "key_fields": ["name", "site"],
        },
        "interface": {
            "fetch_function": nb.dcim.interfaces.all,
            "object_type": "dcim.interfaces",
            "key_fields": ["name", "device"],
        },
        "vminterface": {
            "fetch_function": nb.virtualization.interfaces.all,
            "object_type": "virtualization.interfaces",
            "key_fields": ["name", "virtual_machine"],
        },
        "virtualdisk": {
            "fetch_function": nb.virtualization.virtual_disks.all,
            "object_type": "virtualization.virtual_disks",
            "key_fields": ["name", "virtual_machine"],
        },
    }

    for obj_name, config in objects_to_cache.items():
        fetch_function = config["fetch_function"]
        object_type = config["object_type"]
        key_fields = config["key_fields"]
        obj_start = time.perf_counter()
        obj_count = 0

        try:
            logger.info(f"Pre-caching {obj_name}...")
            for obj in fetch_function():
                get_params = {}
                for key_field in key_fields:
                    value = getattr(obj, key_field, None)
                    if isinstance(value, pynetbox.core.response.Record):
                        value = getattr(value, "id", None)
                    if isinstance(value, int):
                        key_field = f"{key_field}_id"
                    get_params[key_field] = value
                cache_key = hashlib.md5(f"{object_type}|{sorted(get_params.items())}".encode()).hexdigest()
                with cache_lock:
                    object_cache[cache_key] = obj
                obj_count += 1
            total_cached += obj_count
            elapsed = time.perf_counter() - obj_start
            logger.info(f"Finished pre-caching {obj_name}: cached={obj_count} elapsed={elapsed:.2f}s")
        except Exception as e:
            logger.error(f"Error pre-caching {obj_name}: {e}")

    overall_elapsed = time.perf_counter() - overall_start
    logger.info(f"Finished pre-caching all NetBox objects: total_cached={total_cached} elapsed={overall_elapsed:.2f}s")

def fetch_tags(rest_session):
    try:
        cat_dict = {}
        cat_response = rest_session.get("/rest/com/vmware/cis/tagging/category")
        cat_response.raise_for_status()
        for category_id in cat_response.json().get("value", []):
            detail_resp = rest_session.get(f"/rest/com/vmware/cis/tagging/category/id:{category_id}")
            detail_resp.raise_for_status()
            cat_dict[category_id] = detail_resp.json().get("value", {}).get("name")

        tag_dict = {}
        tag_response = rest_session.get("/rest/com/vmware/cis/tagging/tag")
        tag_response.raise_for_status()
        for tag_id in tag_response.json().get("value", []):
            detail_resp = rest_session.get(f"/rest/com/vmware/cis/tagging/tag/id:{tag_id}")
            detail_resp.raise_for_status()
            tag_detail = detail_resp.json().get("value", {})
            tag_dict[tag_id] = {
                "name": tag_detail.get("name"),
                "category_id": tag_detail.get("category_id"),
            }

        vm_response = rest_session.get("/rest/vcenter/vm")
        vm_response.raise_for_status()
        vm_objs = [{"id": vm["vm"], "type": "VirtualMachine"} for vm in vm_response.json().get("value", [])]

        vm_tags = {}
        tag_assoc_payload = {"object_ids": vm_objs}
        assoc_resp = rest_session.post("/rest/com/vmware/cis/tagging/tag-association?~action=list-attached-tags-on-objects", json=tag_assoc_payload)
        assoc_resp.raise_for_status()
        for assoc in assoc_resp.json().get("value", []):
            vm_id = assoc["object_id"]["id"]
            cat_tag_dict = {}
            for tag_id in assoc.get("tag_ids", []):
                tag_info = tag_dict.get(tag_id, {})
                cat_name = cat_dict.get(tag_info.get("category_id"))
                if cat_name not in cat_tag_dict:
                    cat_tag_dict[cat_name] = []
                cat_tag_dict[cat_name].append(tag_info.get("name"))
            vm_tags[vm_id] = cat_tag_dict

        logging.info("Processed Tags")
        return vm_tags

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching VM tags: {e}")
        return {}

def fetch_vmware_data(api_client, rest_session):
    """
    Fetch VMware data including clusters, hosts, virtual machines, and their Distributed Virtual Switch (DVS) VLAN details.
    """
    content = api_client.RetrieveContent()
    clusters = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True).view
    cluster_data = []

    vm_tags = fetch_tags(rest_session)

    for cluster in clusters:
        cluster_entry = {
            "cluster": cluster,
            "cluster_name": cluster.name,
            "hosts": []
        }

        for host in cluster.host:
            host_entry = {
                "host": host,
                "nics": [],
                "vms": [],
            }

            dvs_info = {}
            logger.info(f"Fetching Network Info for {host}")
            for network in host.network:
                if isinstance(network, vim.dvs.DistributedVirtualPortgroup):
                    vlan_config = getattr(network.config.defaultPortConfig.vlan, 'vlanId', None)
                    dvs_info[network.key] = {
                        "id": vlan_config,
                        "name": network.name,
                    }
                    dvs_info[network.name] = {
                        "id": vlan_config,
                        "name": network.name,
                    }

            for pnic in getattr(host.config.network, 'pnic', []):
                nic_entry = {
                    "name": pnic.device,
                    "mac_address": getattr(pnic, 'mac', None),
                    "link_speed": getattr(pnic.linkSpeed, 'speedMb', None),
                    "duplex": getattr(pnic.linkSpeed, 'duplex', None),
                }
                host_entry["nics"].append(nic_entry)
            for vnic in getattr(host.config.network, 'vnic', []):
                portgroup_name = getattr(vnic.spec.distributedVirtualPort, 'portgroupKey', None)
                nic_entry = {
                    "name": vnic.device,
                    "mac_address": getattr(vnic.spec, 'mac', None),
                    "address": getattr(vnic.spec.ip, 'ipAddress', None),
                    "prefix_length": subnet_mask_to_prefix_length(getattr(vnic.spec.ip, 'subnetMask', None)),
                    "vlan": dvs_info.get(portgroup_name) if portgroup_name in dvs_info else None,
                }
                host_entry["nics"].append(nic_entry)

            logger.info(f"Fetching VMs for {host}")

            for vm in host.vm:
                vm_entry = {
                    "vm": vm,
                    "vm_name": vm.name.replace('.clemson.edu', '')[:64],
                    "interfaces": [],
                    "disks": [],
                    "tags": vm_tags.get(vm.name, {})
                }

                logger.info(f"Fetching Network Info for {vm}")
                for net in getattr(vm.guest, 'net', []):
                  if hasattr(net, 'macAddress'):  # Ensure net has a macAddress to match with devices
                    for device in getattr(vm.config.hardware, 'device', []):
                      if isinstance(device, vim.vm.device.VirtualEthernetCard) and net.macAddress == device.macAddress:
                        portgroup_name = getattr(net, "network", None)
                        nic_entry = {
                            "name": device.deviceInfo.label,
                            "mac_address": device.macAddress if hasattr(device, 'macAddress') else None,
                            "enabled": device.connectable.connected if hasattr(device, 'connectable') else False,
                            "vlan": dvs_info.get(portgroup_name) if portgroup_name in dvs_info else None,
                            "description": portgroup_name,
                            "ipv4_addresses": [
                                 {
                                   "address": ip.ipAddress,
                                   "prefix_length": getattr(ip, 'prefixLength', 24),
                                 } for ip in getattr(net.ipConfig, 'ipAddress', []) if ":" not in ip.ipAddress
                            ],
                            "ipv6_addresses": [
                                 {
                                   "address": ip.ipAddress,
                                   "prefix_length": getattr(ip, 'prefixLength', 48),
                                 } for ip in getattr(net.ipConfig, 'ipAddress', []) if ":" in ip.ipAddress
                            ],
                        }
                        vm_entry["interfaces"].append(nic_entry)

                for device in getattr(vm.config.hardware, 'device', []):
                    if isinstance(device, vim.vm.device.VirtualDisk):
                        disk_entry = {
                            "name": device.deviceInfo.label,
                            "capacity": device.capacityInKB / 1024,
                            "datastore": getattr(device.backing.datastore, 'name', None) if hasattr(device.backing, 'datastore') else None,
                            "vmdk": getattr(device.backing, 'fileName', None),
                            "type": getattr(device.backing, 'diskMode', None),
                            "thin": getattr(device.backing, 'thinProvisioned', False),
                        }
                        vm_entry["disks"].append(disk_entry)

                vm_entry["tags"]=vm_tags.get(vm._moId, {})
                host_entry["vms"].append(vm_entry)

            cluster_entry["hosts"].append(host_entry)

        cluster_data.append(cluster_entry)

    return cluster_data

def sanitize_data(data):
    sanitized_data = {}
    for key, value in data.items():
        if hasattr(value, 'id'):
            sanitized_data[key] = value.id
        elif hasattr(value, 'name'):
            sanitized_data[key] = value.name
        else:
            sanitized_data[key] = value

    return sanitized_data

def subnet_mask_to_prefix_length(subnet_mask):
    """Convert an IPv4 subnet mask to a prefix length."""
    try:
        return sum(bin(int(octet)).count('1') for octet in subnet_mask.split('.'))
    except Exception as e:
        logger.error(f"Failed to convert subnet mask {subnet_mask} to prefix length: {e}")
        return None


def create_or_update(object_type, find_function, create_function, update_function, data, protected_fields=None):
    global object_cache

    try:
        key_fields = list(data.keys())[:2]
        if not data[key_fields[0]]:
            logger.error(f"key_field for {object_type} '{key_fields[0]}' has no value {data}")
            return None
        get_params = {}
        logger.debug(f"key fields: {key_fields} out of {data}")
        for key_field in key_fields:
            value = data[key_field]
            if isinstance(value, int) and key_field != 'id' and key_field != 'vid':
                key_field = f"{key_field}_id"
            get_params[key_field] = value
            logger.debug(f"keyfield: {key_field} {value}")

        cache_key = hashlib.md5(f"{object_type}|{sorted(get_params.items())}".encode()).hexdigest()
        response = None
        with cache_lock:
            if cache_key in object_cache:
                logger.debug(f"CACHE: Cache hit for object: {cache_key} {data[list(data.keys())[0]]}")
                response = object_cache[cache_key]
                perf_increment(f"{object_type}.cache.hit")
                log_cache_hit_miss_periodic(object_type)
            else:
                logger.debug(f"CACHE: Cache miss for object: {cache_key} {data[list(data.keys())[0]]}")
                perf_increment(f"{object_type}.cache.miss")
                log_cache_hit_miss_periodic(object_type)

        if response is None:
            get_start = time.perf_counter()
            try:
                response = find_function(**get_params)
                perf_increment(f"{object_type}.get.count")
            except ValueError as e:
                logger.error(f"Error querying {object_type} with params {get_params}: {e}")
                perf_increment(f"{object_type}.get.error")
                response = None
            finally:
                perf_add_time(f"{object_type}.get.time", time.perf_counter() - get_start)

        if response:
            existing_id = response.id if hasattr(response, 'id') else response['id']
            logger.debug(f"Found existing object with ID: {existing_id} {data[list(data.keys())[0]]}")

            existing_data = {}
            for key in data:
                existing_data[key] = getattr(response, key, None)
                if isinstance(existing_data[key], Record):
                    existing_data[key] = existing_data[key].id if hasattr(existing_data[key], 'id') else str(existing_data[key])
                if isinstance(existing_data[key], list) and key in ('tags', 'tagged_vlans'):
                    existing_data[key] = [{'id': item.id} if hasattr(item, 'id') else item for item in existing_data[key]]

            # For virtual machines and devices, preserve protected fields from NetBox
            update_data = data.copy()
            if object_type in ('virtualmachine', 'host') and protected_fields:
                for field in protected_fields:
                    if field in existing_data and existing_data[field] is not None:
                        update_data[field] = existing_data[field]
                        logger.debug(f"Preserving NetBox value for {field} ({existing_data[field]}) for {object_type} {data.get('name')}")

            if object_type == 'virtualdisk' and 'size' in update_data:
                try:
                    update_data['size'] = int(update_data['size'])
                except Exception as e:
                    logger.error(f"Failed to convert size to int for virtualdisk: {update_data['size']} ({e})")

            diff = DeepDiff(existing_data, update_data, ignore_order=True, ignore_string_case=True, report_repetition=True, ignore_type_in_groups=[(int, str, float)])

            if diff:
                logger.debug(f"Updating object {existing_id} {data[list(data.keys())[0]]}: differences detected {diff}")
                update_data['id'] = existing_id
                update_start = time.perf_counter()
                try:
                    update_function([update_data])
                    perf_increment(f"{object_type}.update.count")
                except pynetbox.core.query.RequestError as e:
                    # Re-raise RequestError so it can be handled by caller (e.g., primary IP errors in process_ip_address)
                    perf_increment(f"{object_type}.update.error")
                    raise
                finally:
                    perf_add_time(f"{object_type}.update.time", time.perf_counter() - update_start)
                response = find_function(**get_params)
                with cache_lock:
                    object_cache[cache_key] = response
            else:
                perf_increment(f"{object_type}.update.skipped")
                with cache_lock:
                    object_cache[cache_key] = response
                logger.debug(f"No changes needed for object {existing_id} {data[list(data.keys())[0]]}")

            return existing_id

        # Use 'name' for slug if available and is a string, else fallback to first key as string
        slug_source = data.get('name') if isinstance(data.get('name'), str) else str(data[key_fields[0]])
        data['slug'] = re.sub(r'\W+', '-', slug_source.lower())
        data = sanitize_data(data)
        # Fix: Ensure 'size' is an integer for virtualdisk
        if object_type == 'virtualdisk' and 'size' in data:
            try:
                data['size'] = int(data['size'])
            except Exception as e:
                logger.error(f"Failed to convert size to int for virtualdisk: {data['size']} ({e})")
        logger.info(f"Creating new object: {data[list(data.keys())[0]]}")
        create_start = time.perf_counter()
        try:
            new_object = create_function(data)
            perf_increment(f"{object_type}.create.count")
        except pynetbox.core.query.RequestError as e:
            perf_increment(f"{object_type}.create.error")
            if object_type == 'platform' and 'name' in str(e) and 'already exists' in str(e):
                logger.warning(f"Platform creation failed due to duplicate name: {data}. Attempting to update existing platform.")
                response = find_function(name=data['name'])
                if response:
                    existing_id = response.id
                    data['id'] = existing_id
                    update_data = [data]
                    update_function(update_data)
                    response = find_function(name=data['name'])
                    with cache_lock:
                        object_cache[cache_key] = response
                    return existing_id
                else:
                    logger.error(f"Could not find existing platform with name {data['name']} after duplicate error.")
                    return None
            else:
                raise
        finally:
            perf_add_time(f"{object_type}.create.time", time.perf_counter() - create_start)

        response = find_function(**get_params)
        with cache_lock:
            object_cache[cache_key] = response
        return new_object.id if hasattr(new_object, 'id') else new_object['id']

    except pynetbox.core.query.RequestError:
        # Let RequestError propagate (e.g., primary IP errors in process_ip_address)
        raise
    except Exception as e:
        logger.error(f"Error during create/update for {object_type} with data {data}: {e}")
        logger.error("Traceback details:")
        logger.error(traceback.format_exc())
        return None


def process_related_field(nb, field_name, field_data, find_function, create_function, update_function=None):
    if not field_data:
        logger.error(f"No data provided for related field: {field_name}")
        return None

    logger.debug(f"Processing related field: {field_name} with data: {field_data}")
    related_object = create_or_update(
        field_name, find_function, create_function, update_function, field_data
    )
    if not related_object:
        logger.warning(f"Failed to create or update {field_name} with data: {field_data}")
        return None
    return related_object

def apply_regex_patterns(value, filename):
    original_value=value
    with regex_cache_lock:
        if filename not in regex_cache:
            try:
                with open(f"regex/{filename}", 'r') as file:
                     regex_cache[filename] = [
                        tuple(line.strip().split(',', 1))
                        for line in file if ',' in line
                    ]
            except FileNotFoundError:
                raise Exception(f"Regex patterns file not found: {filename}")
            except Exception as e:
                raise Exception(f"Error reading regex patterns from {filename}: {e}")

    patterns = regex_cache[filename]
    count = 0
    for pattern, replacement in patterns:
        count += 1
        value = re.sub(pattern.strip(), replacement.strip(), value)
    if value == original_value: value = 'Unknown'
    return value


def process_cluster(nb,cluster):
    site = apply_regex_patterns(cluster.name, 'cluster_to_site')
    group =  process_related_field(nb,"clustergroup",{"name": cluster.parent.parent.name if cluster.parent and cluster.parent.parent else "Unknown"},
          nb.virtualization.cluster_groups.get,nb.virtualization.cluster_groups.create,nb.virtualization.cluster_groups.update)
    return {
        "name": cluster.name,
        "group": group,
        "site": process_related_field(nb,"site",{"name": site },nb.dcim.sites.get,nb.dcim.sites.create,nb.dcim.sites.update),
        "type": process_related_field(nb,"clustertype",{"name":"VMWare"},nb.virtualization.cluster_types.get,nb.virtualization.cluster_types.create,nb.virtualization.cluster_types.update),
    }

def process_host(nb,host):
    site = apply_regex_patterns(host.parent.name, 'cluster_to_site')
    manufacturer = process_related_field(nb,"manufacturer",{"name": host.hardware.systemInfo.vendor}, nb.dcim.manufacturers.get, nb.dcim.manufacturers.create, nb.dcim.manufacturers.update)
    tenant = apply_regex_patterns(host.name,'host_to_tenant')
    if tenant == host.name: tenant='Unknown'

    serial_number="Unknown"
    for identifier in host.summary.hardware.otherIdentifyingInfo:
            identifier_value = getattr(identifier, 'identifierValue', None)
            identifier_type = getattr(identifier.identifierType, 'key', None)
            if identifier_type == 'SerialNumberTag':
                serial_number = identifier_value

    return {
        "name": host.name.replace('.clemson.edu', ''),
        "cluster": process_related_field(nb,"cluster",{"name": host.parent.name},nb.virtualization.clusters.get,nb.virtualization.clusters.create,nb.virtualization.clusters.update),
        "site": process_related_field(nb,"site",{"name": site},nb.dcim.sites.get,nb.dcim.sites.create,nb.dcim.sites.update),
        "device_type": process_related_field(nb,"devicetype",{"model": host.hardware.systemInfo.model, "manufacturer": manufacturer },nb.dcim.device_types.get,nb.dcim.device_types.create, nb.dcim.device_types.update),
        "role": process_related_field(nb,"role",{"name": "Hypervisor Host"},nb.dcim.device_roles.get,nb.dcim.device_roles.create, nb.dcim.device_roles.update),
        "status": "active" if host.runtime.connectionState == "connected" else "offline",
        #"tenant": process_related_field(nb,"tenant",{"name": tenant},nb.tenancy.tenants.get,nb.tenancy.tenants.create, nb.tenancy.tenants.update),
        "platform": process_related_field(nb,"platform",{"name": host.config.product.fullName if host.config.product else "Unknown"},nb.dcim.platforms.get,nb.dcim.platforms.create,nb.dcim.platforms.update),
        "serial": serial_number,
    }


def process_vm(nb, vm, host):
    tenant = apply_regex_patterns(vm.name, 'vm_to_tenant')
    role = apply_regex_patterns(vm.name, 'vm_to_role')
    if tenant == vm.name:
        tenant = "Unknown"

    platform_name = vm.guest.guestFullName if vm.guest.guestFullName else None
    platform = None
    if platform_name:
        manufacturer_name = platform_name.split()[0] if platform_name.split() else "Unknown"
        manufacturer = process_related_field(
            nb,
            "manufacturer",
            {"name": manufacturer_name, "slug": re.sub(r'\W+', '-', manufacturer_name.lower())},
            nb.dcim.manufacturers.get,
            nb.dcim.manufacturers.create,
            nb.dcim.manufacturers.update
        )

        if manufacturer:
            platform_data = {
                "name": platform_name,
                "manufacturer": manufacturer,
                "slug": re.sub(r'\W+', '-', platform_name.lower())
            }
            platform = process_related_field(
                nb,
                "platform",
                platform_data,
                nb.dcim.platforms.get,
                nb.dcim.platforms.create,
                nb.dcim.platforms.update
            )
        else:
            logger.warning(f"Skipping platform creation for VM {vm.name}: Failed to create manufacturer {manufacturer_name}")
    else:
        logger.debug(f"No platform name provided for VM {vm.name}; skipping platform assignment")

    cluster_id = process_related_field(
        nb,
        "cluster",
        {"name": vm.runtime.host.parent.name},
        nb.virtualization.clusters.get,
        nb.virtualization.clusters.create,
        nb.virtualization.clusters.update
    )
    logger.debug(f"Resolved cluster ID for VM {vm.name}: {cluster_id}")

    vm_data = {
        "name": vm.name.replace('.clemson.edu', '')[:64],
        "cluster": cluster_id,
        "device": process_related_field(
            nb,
            "device",
            host,
            nb.dcim.devices.get,
            nb.dcim.devices.create,
            nb.dcim.devices.update
        ),
        "role": process_related_field(
            nb,
            "role",
            {"name": role},
            nb.dcim.device_roles.get,
            nb.dcim.device_roles.create,
            nb.dcim.device_roles.update
        ),
        #"tenant": process_related_field(
        #    nb,
        #    "tenant",
        #    {"name": tenant},
        #    nb.tenancy.tenants.get,
        #    nb.tenancy.tenants.create,
        #    nb.tenancy.tenants.update
        #),
        "description": f"{role} VM for {tenant}",
        "status": "active" if vm.runtime.powerState == "poweredOn" else "offline",
        "serial": vm.config.uuid,
        "vcpus": vm.config.hardware.numCPU if vm.config.hardware else 0,
        "memory": vm.config.hardware.memoryMB if vm.config.hardware else 0,
    }

    if platform:
        vm_data["platform"] = platform
    else:
        logger.debug(f"No platform assigned to VM {vm.name}")

    return vm_data

def process_host_interface(nb, nic, host):
    interface_data = {
        "name": nic.get("name"),
        "device": process_related_field(nb, "device", host, nb.dcim.devices.get, nb.dcim.devices.create, nb.dcim.devices.update),
        "description": f"{host['name']} {nic.get('name')}",
        "mac_address": nic.get("mac_address").upper() if nic.get("mac_address") else None,
    }
    
    # Only set physical interface fields (type, speed, duplex) if we have link speed data
    # This prevents trying to change a cable-attached interface to virtual type
    if nic.get("link_speed"):
        type = "other"
        if nic.get("link_speed") == 1000:
            type = "1000base-t"
        elif nic.get("link_speed") == 10000:
            type = "10gbase-x-sfpp"
        elif nic.get("link_speed") == 25000:
            type = "25gbase-x-sfp28"
        elif nic.get("link_speed") == 40000:
            type = "40gbase-x-qsfpp"
        elif nic.get("link_speed") == 100000:
            type = "100gbase-x-qsfp28"
        
        interface_data["type"] = type
        interface_data["speed"] = nic.get("link_speed") * 1000
        interface_data["duplex"] = ("full" if nic.get("duplex") else "half") if nic.get("duplex") else None

    # Set mode to 'tagged' if VLANs are expected
    if nic.get("vlan") and isinstance(nic.get("vlan"), dict) and nic.get("vlan").get("id"):
        interface_data["mode"] = "tagged"

    return interface_data

def process_vm_interface(nb, interface, vm):
    return {
        "name": interface.get("name"),
        "virtual_machine": process_related_field(nb,"vm",{"name": vm.get('name'), "cluster": vm.get('cluster')},nb.virtualization.virtual_machines.get,nb.virtualization.virtual_machines.create,nb.virtualization.virtual_machines.update),
        "description": f"{vm.get('name')} {interface.get('name')}",
        "mac_address": interface.get("mac_address").upper(),
        "enabled": interface.get("enabled")
    }

def process_disk(nb, disk, vm):
    return {
        "name": disk.get("name"),
        "virtual_machine": process_related_field(nb,"vm",{"name": vm.get('name'), "cluster": vm.get('cluster')},nb.virtualization.virtual_machines.get,nb.virtualization.virtual_machines.create,nb.virtualization.virtual_machines.update),
        "size": disk.get("capacity"),
        "description": f'{disk.get("vmdk")} ({"Thin Provisioned" if disk.get("thin") else "Thick Provisioned"} {disk.get("type")})'
    }


def clear_primary_ip_for_address(nb, ip_address_str):
    """
    Clear primary IP references for a given IP address to allow reassignment.
    Returns True if any primary IPs were cleared, False otherwise.
    """
    try:
        # Find the IP address object
        ip_obj = nb.ipam.ip_addresses.get(address=ip_address_str)
        if not ip_obj:
            return False
        
        ip_id = ip_obj.id
        cleared = False
        
        if hasattr(ip_obj, 'assigned_object_id') and ip_obj.assigned_object_id:
            assigned_type = getattr(ip_obj, 'assigned_object_type', None)
            
            # Check if this IP is primary on a device
            if assigned_type == 'dcim.interface':
                interface = nb.dcim.interfaces.get(ip_obj.assigned_object_id)
                if interface and interface.device:
                    device = nb.dcim.devices.get(interface.device.id)
                    if device:
                        if hasattr(device, 'primary_ip4') and device.primary_ip4 and device.primary_ip4.id == ip_id:
                            logger.info(f"Clearing primary IPv4 on device {device.id} for IP {ip_address_str}")
                            nb.dcim.devices.update([{"id": device.id, "primary_ip4": None}])
                            cleared = True
                        if hasattr(device, 'primary_ip6') and device.primary_ip6 and device.primary_ip6.id == ip_id:
                            logger.info(f"Clearing primary IPv6 on device {device.id} for IP {ip_address_str}")
                            nb.dcim.devices.update([{"id": device.id, "primary_ip6": None}])
                            cleared = True
            
            # Check if this IP is primary on a VM
            elif assigned_type == 'virtualization.vminterface':
                vminterface = nb.virtualization.interfaces.get(ip_obj.assigned_object_id)
                if vminterface and vminterface.virtual_machine:
                    vm = nb.virtualization.virtual_machines.get(vminterface.virtual_machine.id)
                    if vm:
                        if hasattr(vm, 'primary_ip4') and vm.primary_ip4 and vm.primary_ip4.id == ip_id:
                            logger.info(f"Clearing primary IPv4 on VM {vm.id} for IP {ip_address_str}")
                            nb.virtualization.virtual_machines.update([{"id": vm.id, "primary_ip4": None}])
                            cleared = True
                        if hasattr(vm, 'primary_ip6') and vm.primary_ip6 and vm.primary_ip6.id == ip_id:
                            logger.info(f"Clearing primary IPv6 on VM {vm.id} for IP {ip_address_str}")
                            nb.virtualization.virtual_machines.update([{"id": vm.id, "primary_ip6": None}])
                            cleared = True
        
        return cleared
    except Exception as e:
        logger.warning(f"Error while clearing primary IP references for {ip_address_str}: {e}")
        return False


def process_ip_address(nb, ip, parent_object, vlan_id, is_primary=False):
    if not parent_object.get("id"):
        logger.error(f"Cannot process IP address {ip['address']} for {parent_object.get('description', 'unknown object')}: Invalid assigned_object_id")
        return None

    ip_data = {
        "address": f"{ip['address']}/{ip['prefix_length']}",
        "status": "active",
        "description": parent_object['description'] if 'description' in parent_object else " ",
        "assigned_object_type": 'dcim.interface' if 'device' in parent_object else 'virtualization.vminterface',
        "assigned_object_id": parent_object.get("id"),
        "tags": ip.get("tags", [])
    }

    # Try to create or update the IP address
    try:
        ip_object = create_or_update(
            'ip_address',
            nb.ipam.ip_addresses.get,
            nb.ipam.ip_addresses.create,
            nb.ipam.ip_addresses.update,
            ip_data
        )
    except pynetbox.core.query.RequestError as e:
        # Check if the error is about primary IP reassignment
        if 'Cannot reassign IP address while it is designated as the primary IP' in str(e):
            logger.debug(f"IP {ip_data['address']} is designated as primary, clearing primary references and retrying")
            # Clear the primary IP references
            if clear_primary_ip_for_address(nb, ip_data['address']):
                # Retry the operation
                try:
                    ip_object = create_or_update(
                        'ip_address',
                        nb.ipam.ip_addresses.get,
                        nb.ipam.ip_addresses.create,
                        nb.ipam.ip_addresses.update,
                        ip_data
                    )
                except Exception as retry_error:
                    logger.error(f"Failed to create/update IP {ip_data['address']} after clearing primary references: {retry_error}")
                    return None
            else:
                logger.error(f"Failed to clear primary IP references for {ip_data['address']}")
                return None
        else:
            # Re-raise if it's a different error
            raise

    obj = {}
    if is_primary and ip_object:
        if ":" not in ip["address"]:
            obj['primary_ip4'] = ip_object
        else:
            obj['primary_ip6'] = ip_object
        logger.debug(f"Setting {ip['address']} as primary IP for {parent_object}")
        if "device" in parent_object:
            obj['id'] = parent_object['device']
            nb.dcim.devices.update([obj])
        elif "virtual_machine" in parent_object:
            obj['id'] = parent_object['virtual_machine']
            nb.virtualization.virtual_machines.update([obj])

    prefix = calculate_network_address(ip['address'], ip['prefix_length'])

    # Skip VLAN assignment for link-local addresses (fe80::/10 and 169.254.0.0/16) as they change frequently
    is_link_local = prefix.startswith('fe80::') or prefix.startswith('169.254.')

    if (":" in prefix and ip['prefix_length'] < 128) or (":" not in prefix and ip['prefix_length'] < 32):
        logger.debug(f"Processing IP Prefix {prefix}/{ip['prefix_length']}")
        prefix_data = {
            "prefix": f"{prefix}/{ip['prefix_length']}",
            "status": "active",
            "tags": ip.get("tags", [])
        }
        if isinstance(vlan_id, int) and not is_link_local:
            prefix_data['vlan'] = vlan_id
            logger.debug(f"Assigned VLAN {vlan_id} to prefix {prefix}/{ip['prefix_length']}")
        elif is_link_local:
            logger.debug(f"Skipping VLAN assignment for link-local prefix {prefix}/{ip['prefix_length']}")
        prefix_object = create_or_update(
            'prefix',
            nb.ipam.prefixes.get,
            nb.ipam.prefixes.create,
            nb.ipam.prefixes.update,
            prefix_data
        )

    return ip_object

def process_vlan(nb, vlan, site_id=None):
    """
    Process a VLAN and return its ID, or None if processing fails.
    """
    if not vlan or not isinstance(vlan, dict) or not vlan.get('id') or not vlan.get('name'):
        logger.error(f"Invalid VLAN data: {vlan}. Skipping VLAN processing.")
        return None

    try:
        vlan_id = int(vlan['id'])  # Ensure VLAN ID is a valid integer
        if vlan_id < 1 or vlan_id > 4094:
            logger.error(f"Invalid VLAN ID {vlan_id}. Must be between 1 and 4094.")
            return None

        vlan_data = {
            "vid": vlan_id,
            "name": f"VLAN{vlan_id}",
            "description": f"VLAN{vlan_id} : {vlan.get('name', 'Unknown')}",
            "tags": vlan.get('tags', []),
        }
        
        logger.debug(f"Processing VLAN with data: {vlan_data}")
        vlan_object = create_or_update(
            'vlan',
            nb.ipam.vlans.get,
            nb.ipam.vlans.create,
            nb.ipam.vlans.update,
            vlan_data
        )

        if not vlan_object:
            logger.error(f"Failed to create or update VLAN with data: {vlan_data}")
            return None

        return vlan_object

    except ValueError as e:
        logger.error(f"Invalid VLAN ID format in {vlan}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error processing VLAN {vlan}: {e}")
        return None

def process_tags(nb, vm_name, tags, cluster_id=None):
    """
    Process and merge existing and new tags for the VM, ensuring no overwriting.
    Returns a list of tag dictionaries with 'id'.
    """
    # Fetch the existing VM to get current tags
    query_params = {"name": vm_name}
    if cluster_id:
        query_params["cluster_id"] = cluster_id
    else:
        logger.warning(f"No cluster_id provided for VM {vm_name}; querying by name alone may return multiple results")

    try:
        vm = nb.virtualization.virtual_machines.get(**query_params)
    except ValueError as e:
        logger.error(f"Error fetching VM {vm_name} with params {query_params}: {e}")
        return []  # Return empty list to avoid breaking the sync
    except Exception as e:
        logger.error(f"Unexpected error fetching VM {vm_name}: {e}")
        return []

    existing_tag_ids = []
    if vm and hasattr(vm, 'tags'):
        existing_tag_ids = [{"id": tag.id} for tag in vm.tags]
    logger.debug(f"Existing tags for VM {vm_name}: {existing_tag_ids}")

    # Process new tags from vCenter
    new_tag_ids = []
    for category, tag_list in tags.items():
        for tag in tag_list:
            full_tag_name = f"{category}:{tag}"
            tag_data = create_or_update(
                "tag",
                nb.extras.tags.get,
                nb.extras.tags.create,
                nb.extras.tags.update,
                {"name": full_tag_name}
            )
            if tag_data and {"id": tag_data} not in new_tag_ids:
                new_tag_ids.append({"id": tag_data})
    logger.debug(f"New tags from vCenter for VM {vm_name}: {new_tag_ids}")

    # Ensure 'VMWare-Sync' tag is included
    vm_sync_tag_data = create_or_update(
        "tag",
        nb.extras.tags.get,
        nb.extras.tags.create,
        nb.extras.tags.update,
        {"name": "VMWare-Sync"}
    )
    if vm_sync_tag_data and {"id": vm_sync_tag_data} not in new_tag_ids:
        new_tag_ids.append({"id": vm_sync_tag_data})
    logger.debug(f"New tags after adding VMWare-Sync for VM {vm_name}: {new_tag_ids}")

    # Merge existing and new tags, avoiding duplicates
    merged_tag_ids = existing_tag_ids[:]
    for new_tag in new_tag_ids:
        if new_tag not in merged_tag_ids:
            merged_tag_ids.append(new_tag)
    logger.debug(f"Merged tags for VM {vm_name}: {merged_tag_ids}")

    return merged_tag_ids

def calculate_network_address(ip, prefix_length):
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return str(network.network_address)
    except ValueError as e:
        logger.error(f"Error calculating network address for IP {ip}/{prefix_length}: {e}")
        return None

def process_host_and_nested(host_entry, netbox_url, netbox_token):
    logger.info(f"Processing host: {host_entry['host'].name}")

    thread_name = f"Host-{host_entry['host'].name}"
    threading.current_thread().name = thread_name

    nb = pynetbox.api(netbox_url, token=netbox_token)
    nb.http_session.verify = False
    nb.http_session.headers.update({"User-Agent": "netbox-vcenter-sync/0.0.1"})

    host_data = process_host(nb, host_entry["host"])

    create_or_update('host', nb.dcim.devices.get, nb.dcim.devices.create, nb.dcim.devices.update, host_data, protected_fields=PROTECTED_FIELDS)

    is_primary = True
    for interface_entry in host_entry["nics"]:
        logger.debug(f"Processing NIC: {interface_entry['name']} for host: {host_entry['host'].name}")
        interface_data = process_host_interface(nb, interface_entry, host_data)

        vlan_data = None
        if 'vlan' in interface_entry and isinstance(interface_entry['vlan'], dict) and interface_entry['vlan'].get('id'):
            logger.debug(f"Processing VLAN: {interface_entry['vlan']} for interface: {interface_entry['name']}")
            interface_entry['vlan']['tags'] = [{"id": create_or_update("tag", nb.extras.tags.get, nb.extras.tags.create, nb.extras.tags.update, {"name": "VMWare-Sync"})}]
            vlan_data = process_vlan(nb, interface_entry['vlan'], site_id=host_data.get('site'))
            if vlan_data:
                interface_data['tagged_vlans'] = [vlan_data]
                interface_data['mode'] = 'tagged'
            else:
                logger.warning(f"Failed to process VLAN for interface {interface_entry['name']}; skipping VLAN assignment")

        interface_data['id'] = create_or_update('interface', nb.dcim.interfaces.get, nb.dcim.interfaces.create, nb.dcim.interfaces.update, interface_data)
        if not interface_data['id']:
            logger.error(f"Failed to create or update interface {interface_entry['name']} for host {host_entry['host'].name}; skipping IP address assignment")
            continue

        if 'address' in interface_entry:
            logger.debug(f"Processing IP address: {interface_entry['address']} for interface: {interface_entry['name']}")
            ip_data = {
                "address": interface_entry.get("address"),
                "prefix_length": interface_entry.get("prefix_length", "64" if ':' in interface_entry.get("address", "") else 24),
                "tags": [{"id": create_or_update("tag", nb.extras.tags.get, nb.extras.tags.create, nb.extras.tags.update, {"name": "VMWare-Sync"})}]
            }
            ip_result = process_ip_address(nb, ip_data, interface_data, vlan_data, is_primary)
            is_primary = False

    for vm_entry in host_entry["vms"]:
        if 'Z-VRA' in vm_entry["vm"].name or 'ISO' in vm_entry["vm"].name or 'emplate' in vm_entry["vm"].name:
            continue

        logger.info(f"Processing virtual machine: {vm_entry['vm'].name}")
        vm_data = process_vm(nb, vm_entry["vm"], host_data)
        vm_data['tags'] = process_tags(
            nb,
            vm_entry["vm"].name,
            vm_entry['tags'],
            cluster_id=vm_data.get('cluster')
        )
        create_or_update('virtualmachine', nb.virtualization.virtual_machines.get, nb.virtualization.virtual_machines.create, nb.virtualization.virtual_machines.update, vm_data, protected_fields=PROTECTED_FIELDS)

        is_primary = True
        vlan_data = None
        for interface_entry in vm_entry["interfaces"]:
            logger.debug(f"Processing interface: {interface_entry['name']} for VM: {vm_entry['vm'].name}")
            vm_interface_data = process_vm_interface(nb, interface_entry, vm_data)

            if 'vlan' in interface_entry and isinstance(interface_entry['vlan'], dict) and interface_entry['vlan'].get('id'):
                logger.debug(f"Processing VLAN: {interface_entry['vlan']} for interface: {interface_entry['name']}")
                interface_entry['vlan']['tags'] = [{"id": create_or_update("tag", nb.extras.tags.get, nb.extras.tags.create, nb.extras.tags.update, {"name": "VMWare-Sync"})}]
                vlan_data = process_vlan(nb, interface_entry['vlan'], site_id=host_data.get('site'))
                if vlan_data:
                    vm_interface_data['tagged_vlans'] = [vlan_data]
                    vm_interface_data['mode'] = 'tagged'
                else:
                    logger.warning(f"Failed to process VLAN for VM interface {interface_entry['name']}; skipping VLAN assignment")

            vm_interface_data['tags'] = [{"id": create_or_update("tag", nb.extras.tags.get, nb.extras.tags.create, nb.extras.tags.update, {"name": "VMWare-Sync"})}]
            vm_interface_data['id'] = create_or_update('vminterface', nb.virtualization.interfaces.get, nb.virtualization.interfaces.create, nb.virtualization.interfaces.update, vm_interface_data)
            if not vm_interface_data['id']:
                logger.error(f"Failed to create or update VM interface {interface_entry['name']} for VM {vm_entry['vm'].name}; skipping IP address assignment")
                continue

            ipv4_addresses = interface_entry.get("ipv4_addresses", [])
            ipv6_addresses = interface_entry.get("ipv6_addresses", [])
            if isinstance(ipv4_addresses, dict):
                ipv4_addresses = [ipv4_addresses]
            elif not isinstance(ipv4_addresses, list):
                ipv4_addresses = []
            if isinstance(ipv6_addresses, dict):
                ipv6_addresses = [ipv6_addresses]
            elif not isinstance(ipv6_addresses, list):
                ipv6_addresses = []
            all_ip_addresses = ipv4_addresses + ipv6_addresses

            for ip_entry in all_ip_addresses:
                if not isinstance(ip_entry, dict):
                    continue
                logger.debug(f"Processing IP Address: {ip_entry.get('address')} for interface: {interface_entry['name']}")
                ip_data = {
                    "address": ip_entry.get("address"),
                    "prefix_length": ip_entry.get("prefix_length", "64" if ':' in ip_entry.get("address") else 24),
                    "tags": [{"id": create_or_update("tag", nb.extras.tags.get, nb.extras.tags.create, nb.extras.tags.update, {"name": "VMWare-Sync"})}]
                }
                ip_result = process_ip_address(nb, ip_data, vm_interface_data, vlan_data, is_primary)
                is_primary = False

        for disk_entry in vm_entry["disks"]:
            logger.debug(f"Processing disk: {disk_entry['name']} for VM: {vm_entry['vm'].name}")
            disk_data = process_disk(nb, disk_entry, vm_data)
            create_or_update('virtualdisk', nb.virtualization.virtual_disks.get, nb.virtualization.virtual_disks.create, nb.virtualization.virtual_disks.update, disk_data)

    return host_entry["host"].name

def process_vmware_data(vcenter, username, password, netbox_url, netbox_token, rest_session):
    global object_cache
    logger.info(f"Processing vCenter: {vcenter}")

    try:
        api_client = SmartConnect(host=vcenter, user=username, pwd=password, sslContext=ssl_context)
    except Exception as e:
        logger.error(f"Failed to connect to vCenter {vcenter} via SmartConnect: {e}")
        logger.error("Traceback details:")
        logger.error(traceback.format_exc())
        return []

    try:
        cluster_data = fetch_vmware_data(api_client, rest_session)
        if cluster_data is None:
            logger.error(f"fetch_vmware_data returned None for vCenter {vcenter}")
            return []
        if not cluster_data:
            logger.warning(f"No cluster data retrieved from vCenter {vcenter}")
            return []

        logger.debug(f"Retrieved {len(cluster_data)} cluster(s) from vCenter {vcenter}")

        nb = pynetbox.api(netbox_url, token=netbox_token)
        nb.http_session.verify = False
        nb.http_session.headers.update({"User-Agent": "netbox-vcenter-sync/0.0.1"})

        max_host_workers = get_env_int("MAX_HOST_WORKERS", 5, min_value=1)

        logger.info(f"Processing hosts in vCenter {vcenter} with {max_host_workers} parallel workers")

        with ThreadPoolExecutor(max_workers=max_host_workers) as executor:
            futures = []

            for cluster_entry in cluster_data:
                if 'Staging' in cluster_entry['cluster'].name:
                    logger.debug(f"Skipping staging cluster: {cluster_entry['cluster'].name}")
                    continue

                logger.info(f"Processing cluster: {cluster_entry['cluster'].name}")
                cluster_data_entry = process_cluster(nb, cluster_entry["cluster"])

                cluster_id = create_or_update(
                    'cluster',
                    nb.virtualization.clusters.get,
                    nb.virtualization.clusters.create,
                    nb.virtualization.clusters.update,
                    cluster_data_entry,
                )
                if not cluster_id:
                    logger.error(f"Failed to create/update cluster {cluster_entry['cluster'].name}")
                    continue

                for host_entry in cluster_entry["hosts"]:
                    logger.debug(f"Submitting host {host_entry['host'].name} for processing")
                    futures.append(executor.submit(process_host_and_nested, host_entry, netbox_url, netbox_token))

            for future in as_completed(futures):
                try:
                    result = future.result()
                    logger.info(f"Completed processing for host: {result}")
                except Exception as e:
                    logger.error(f"Error processing host: {e}")
                    logger.error("Traceback details:")
                    logger.error(traceback.format_exc())

        logger.info(f"Completed processing vCenter {vcenter} with {len(cluster_data)} cluster(s)")
        return cluster_data

    except Exception as e:
        logger.error(f"Error in process_vmware_data for vCenter {vcenter}: {e}")
        logger.error("Traceback details:")
        logger.error(traceback.format_exc())
        return []
    finally:
        try:
            Disconnect(api_client)
            logger.debug(f"Disconnected from vCenter {vcenter}")
        except Exception as e:
            logger.error(f"Error disconnecting from vCenter {vcenter}: {e}")


def extract_vcenter_vm_names_and_clusters(vcenter_vms):
    """
    Extract VM names and cluster names from cluster data structure.
    Returns tuple: (set of VM names, set of cluster names)
    """
    vcenter_vm_names = set()
    processed_clusters = set()
    
    # Flatten all clusters from all vCenters into a single list
    flat_clusters = []
    for entry in vcenter_vms:
        if isinstance(entry, list):
            flat_clusters.extend(entry)
        elif isinstance(entry, dict):
            flat_clusters.append(entry)
    
    if not flat_clusters:
        logger.error("No valid cluster data found in vCenter VMs")
        return vcenter_vm_names, processed_clusters
    
    logger.debug(f"Extracting VM names and clusters from {len(flat_clusters)} clusters")
    
    for cluster in flat_clusters:
        # Extract cluster name from cached string
        cluster_name = cluster.get('cluster_name')
        if cluster_name:
            processed_clusters.add(cluster_name)
        
        # Extract VM names
        for host in cluster.get('hosts', []):
            for vm in host.get('vms', []):
                try:
                    if vm and isinstance(vm, dict):
                        if vm.get('vm_name'):
                            vcenter_vm_names.add(vm['vm_name'])
                        elif vm.get('vm') and hasattr(vm['vm'], 'name'):
                            name = vm['vm'].name.replace('.clemson.edu', '')[:64]
                            vcenter_vm_names.add(name)
                except Exception as e:
                    logger.warning(f"Error extracting VM name from cluster data: {e}")
                    continue
    
    logger.debug(f"Extracted {len(vcenter_vm_names)} VM names from {len(processed_clusters)} clusters")
    return vcenter_vm_names, processed_clusters


def mark_decommissioned_vms(nb, vcenter_vm_names, processed_clusters):
    """
    Mark VMs in NetBox that are not in vCenter with status 'decommissioning', skipping those already marked.
    Only checks VMs in clusters that were actually processed.
    """
    logger.info("Starting decommissioning VM status update process.")

    # Validate inputs
    if not vcenter_vm_names:
        logger.warning("No vCenter VM names provided for decommissioning check")
        return
    
    if not processed_clusters:
        logger.warning("No processed clusters provided; skipping decommissioning check to avoid false positives")
        return

    logger.info(f"Processing decommissioning for {len(vcenter_vm_names)} VMs across {len(processed_clusters)} clusters")
    logger.debug(f"Processed clusters: {', '.join(sorted(processed_clusters))}")
    
    # Show sample of vCenter VM names for debugging
    sample_vms = list(vcenter_vm_names)[:5]
    logger.debug(f"Sample vCenter VM names: {sample_vms}")

    # Get cluster IDs for processed clusters
    cluster_ids = []
    for cluster_name in processed_clusters:
        try:
            cluster = nb.virtualization.clusters.get(name=cluster_name)
            if cluster:
                cluster_ids.append(cluster.id)
        except Exception as e:
            logger.warning(f"Could not find cluster {cluster_name} in NetBox: {e}")
    
    if not cluster_ids:
        logger.warning("No valid cluster IDs found; skipping decommissioning check")
        return
    
    logger.debug(f"Found {len(cluster_ids)} cluster IDs to check: {cluster_ids}")

    # Get all VMs in NetBox with the VMWare-Sync tag in processed clusters (including decommissioning ones)
    try:
        netbox_vms = nb.virtualization.virtual_machines.filter(
            tag="vmware-sync", 
            cluster_id=cluster_ids
        )
        netbox_vm_count = len(list(netbox_vms))
        logger.info(f"Found {netbox_vm_count} NetBox VMs to check for status updates")
    except Exception as e:
        logger.error(f"Error fetching NetBox VMs: {e}")
        return

    marked_decom_count = 0
    reactivated_count = 0
    for vm in netbox_vms:
        vm_name = vm.name
        current_status = vm.status.value if hasattr(vm.status, 'value') else str(vm.status)
        
        # Check if VM has a cluster
        if not vm.cluster:
            logger.warning(f"Skipping VM {vm_name}: No cluster associated")
            continue
        
        cluster_name = vm.cluster.name
        cluster_id = vm.cluster.id

        # If VM not found in vCenter data, mark as decommissioning
        if vm_name not in vcenter_vm_names:
            # Only update if not already decommissioning (to avoid resetting last_updated timestamp)
            if current_status != 'decommissioning':
                logger.info(f"Marking VM {vm_name} (current status: {current_status}) in cluster {cluster_name} as decommissioning")
                try:
                    # Update VM status to decommissioning
                    vm_data = {
                        "id": vm.id,
                        "status": "decommissioning",
                        "name": vm_name,
                        "cluster": cluster_id,
                    }
                    nb.virtualization.virtual_machines.update([vm_data])
                    marked_decom_count += 1
                    logger.debug(f"Successfully updated VM {vm_name} status to decommissioning")
                except Exception as e:
                    logger.error(f"Error updating VM {vm_name} to decommissioning: {e}")
            else:
                logger.debug(f"VM {vm_name} already decommissioning, preserving timestamp")
        else:
            # VM found in vCenter - if it's decommissioning, reactivate it
            if current_status == 'decommissioning':
                logger.info(f"Reactivating VM {vm_name} (was decommissioning) in cluster {cluster_name} - found in vCenter")
                try:
                    # Update VM status back to active
                    vm_data = {
                        "id": vm.id,
                        "status": "active",
                        "name": vm_name,
                        "cluster": cluster_id,
                    }
                    nb.virtualization.virtual_machines.update([vm_data])
                    reactivated_count += 1
                    logger.debug(f"Successfully reactivated VM {vm_name}")
                except Exception as e:
                    logger.error(f"Error reactivating VM {vm_name}: {e}")
            else:
                logger.debug(f"VM {vm_name} found in vCenter with status {current_status}; no status change needed")
    
    logger.info(f"Status updates: marked={marked_decom_count} decommissioning, reactivated={reactivated_count}")


def delete_stale_decommissioned_vms(nb, decom_days):
    """
    Delete VMs with status 'decommissioning' that haven't been modified in the configured number of days.
    """
    logger.info("Starting deletion of stale decommissioned VMs.")

    try:
        # Get VMs with decommissioning status
        decom_vms = nb.virtualization.virtual_machines.filter(tag="vmware-sync",status="decommissioning")
    except Exception as e:
        logger.error(f"Error fetching decommissioning VMs: {e}")
        return

    try:
        decom_days_int = int(decom_days)
    except (TypeError, ValueError):
        logger.warning(f"Invalid DECOM_DAYS value '{decom_days}', defaulting to 5")
        decom_days_int = 5

    cutoff_date = datetime.datetime.now().astimezone() - datetime.timedelta(days=decom_days_int)

    for vm in decom_vms:
        last_updated = vm.last_updated
        if not last_updated:
            logger.warning(f"Skipping VM {vm.name}: No last_updated timestamp")
            continue

        # Parse ISO format datetime string
        try:
            if isinstance(last_updated, str):
                last_updated = datetime.datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
        except (ValueError, AttributeError) as e:
            logger.warning(f"Skipping VM {vm.name}: Could not parse last_updated timestamp '{last_updated}': {e}")
            continue

        if last_updated < cutoff_date:
            logger.info(f"Deleting stale VM {vm.name} (last updated: {last_updated})")
            try:
                # NetBox cascades deletes through FK relationships
                # Deleting the VM will automatically delete:
                # - Virtual machine interfaces (which will delete their associated IPs)
                # - Virtual disks
                vm.delete()
                logger.info(f"Successfully deleted VM {vm.name}")
            except Exception as e:
                logger.error(f"Error deleting VM {vm.name}: {e}")
        else:
            logger.info(f"Not deleting VM {vm.name} yet. (last updated: {last_updated})")




def process_single_vcenter(vcenter, username, password, netbox_url, netbox_token):
    """
    Process a single vCenter: authenticate and sync all data.
    Returns cluster_data list or None on failure.
    """
    logger.info(f"Processing vCenter: {vcenter}")
    
    # Authenticate to vCenter REST API
    session = RelativeSession(f'https://{vcenter}')
    session.headers.update({"Content-Type": "application/json"})
    login_url = f"/rest/com/vmware/cis/session"
    try:
        response = session.post(login_url, auth=(username, password))
        response.raise_for_status()
        logger.debug(f"Authenticated with vCenter {vcenter}")
    except Exception as e:
        logger.error(f"Failed to authenticate with vCenter {vcenter}: {e}")
        logger.error("Traceback details:")
        logger.error(traceback.format_exc())
        return None

    # Process vCenter data
    try:
        cluster_data = process_vmware_data(vcenter, username, password, netbox_url, netbox_token, session)
        if cluster_data and isinstance(cluster_data, list):
            logger.info(f"Successfully retrieved cluster data with {len(cluster_data)} cluster(s) from vCenter {vcenter}")
            return cluster_data
        else:
            logger.warning(f"Invalid or empty cluster data returned from vCenter {vcenter}: {cluster_data}")
            return None
    except Exception as e:
        logger.error(f"Error processing vCenter {vcenter}: {e}")
        logger.error("Traceback details:")
        logger.error(traceback.format_exc())
        return None


def main():
    # Read vcenters.txt as a list of vcenter hostnames (one per line, skip blanks/comments)
    with open("vcenters.txt", "r") as f:
        vcenters = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    # Load credentials and URLs from environment variables
    username = os.environ.get("VCENTER_USERNAME")
    password = os.environ.get("VCENTER_PASSWORD")
    netbox_url = os.environ.get("NETBOX_URL")
    netbox_token = os.environ.get("NETBOX_TOKEN")
    decom_days = os.environ.get("DECOM_DAYS", 5)

    if not (username and password and netbox_url and netbox_token):
        logger.error("Missing required environment variables for credentials or NetBox connection.")
        return

    # Warm object cache in background so VMware sync starts immediately
    logger.info("Starting background NetBox pre-cache thread")
    precache_thread = start_background_precache(netbox_url, netbox_token)

    # Process vCenters in parallel
    all_cluster_data = []
    default_vcenter_workers = min(len(vcenters), 3)
    max_vcenter_workers = get_env_int("MAX_VCENTER_WORKERS", default_vcenter_workers, min_value=1)
    logger.info(f"Processing {len(vcenters)} vCenter(s) with {max_vcenter_workers} parallel workers")
    
    with ThreadPoolExecutor(max_workers=max_vcenter_workers) as executor:
        # Submit all vCenter processing jobs
        future_to_vcenter = {
            executor.submit(process_single_vcenter, vcenter, username, password, netbox_url, netbox_token): vcenter
            for vcenter in vcenters
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_vcenter):
            vcenter = future_to_vcenter[future]
            try:
                cluster_data = future.result()
                if cluster_data:
                    all_cluster_data.append(cluster_data)
                    logger.info(f"Completed processing vCenter: {vcenter}")
                else:
                    logger.warning(f"No data retrieved from vCenter: {vcenter}")
            except Exception as e:
                logger.error(f"Exception while processing vCenter {vcenter}: {e}")
                logger.error("Traceback details:")
                logger.error(traceback.format_exc())

    # After syncing all vCenters, mark and delete decommissioned VMs
    if not all_cluster_data:
        logger.error("No valid vCenter data retrieved; skipping decommissioning and deletion")
        return

    logger.info(f"Collected data from {len(all_cluster_data)} vCenter(s)")
    nb = pynetbox.api(netbox_url, token=netbox_token)
    nb.http_session.verify = False
    nb.http_session.headers.update({"User-Agent": "netbox-vcenter-sync/0.0.1"})

    # Extract VM names and cluster names from cluster data
    vcenter_vm_names, processed_clusters = extract_vcenter_vm_names_and_clusters(all_cluster_data)
    logger.info(f"Extracted {len(vcenter_vm_names)} VM names from {len(processed_clusters)} clusters for decommissioning check")
    
    mark_decommissioned_vms(nb, vcenter_vm_names, processed_clusters)
    delete_stale_decommissioned_vms(nb, decom_days)
    log_performance_summary()

if __name__ == "__main__":
    main()
