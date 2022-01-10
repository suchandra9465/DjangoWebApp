from network_helper import expand_address
from zone import get_zone, get_zone2


def get_zones(context, address_obj, config):
    zones = []

    for address in expand_address(config[context]['addresses'], address_obj, config[context][
        'addressmappings']):  # expand_address(config[context]['addresses'], route_dest, config[context]['addressmappings']):
        for network in config[context]['addresses'][address]['IPv4Networks']:
            tmp_zone = get_zone(context, '{}'.format(network[0]), config)
            if tmp_zone not in zones:
                zones.append(tmp_zone)
    return zones


def get_zones2(context, address_obj, tmpconfig=None):
    zones = []

    if tmpconfig:
        config = tmpconfig

    for address in expand_address(config[context]['addresses'], address_obj, config[context][
        'addressmappings']):  # expand_address(config[context]['addresses'], route_dest, config[context]['addressmappings']):
        for network in config[context]['addresses'][address]['IPv4Networks']:
            tmp_zones = get_zone2(context, '{}'.format(network), config)
            for tmp_zone in tmp_zones:
                if tmp_zone not in zones:
                    zones.append(tmp_zone)
    return zones
