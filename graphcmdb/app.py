import json
import datetime
import os
import pprint
import traceback
from collections.abc import Mapping, Sequence
from decimal import Decimal
from gremlin_python import statics
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection

statics.load_statics(globals())
g = traversal().withRemote(DriverRemoteConnection(os.environ['NEPTUNE_ENDPOINT'], 'g'))
pp = pprint.PrettyPrinter(indent=4)


def datetime_parser(dct):
    for k, v in dct.items():
        if isinstance(v, str):
            try:
                dct[k] = datetime.datetime.strptime(v, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                pass

    return dct


def reformat_resource_type(rt):
    return rt.replace('::', '-')


def insert_or_update_config_item(rid, cit, rname):
    return g.V().hasId(rid).fold().coalesce(unfold(), addV(cit).property(id, rid).property('resourceName', rname))


def insert_or_update_relationship(from_id, to_id, relationship):
    return g.V().hasId(from_id).as_('v').V().hasId(to_id).coalesce(inE(relationship).where(outV().as_('v')),
                                                                   addE(relationship).from_('v'))


def delete_config_item(rid):
    g.V(rid).drop().iterate()


def delete_relationship(from_id, to_id, relationship):
    g.V(from_id).bothE().hasLabel(relationship).where(otherV().hasId(to_id)).drop().iterate()


def add_property(t, propkey, propval):
    if propval:
        if not isinstance(propval, dict) and not isinstance(propval, list):
            if isinstance(propval, datetime.date):
                # shouldn't have to do this, however for some reason cytoscape-plugin silently swallows some
                # exception when importing properties that are of 'datetime'
                t.property(single, propkey, str(propval))
            else:
                t.property(single, propkey, str(propval))

    return t


def add_properties(props, t):
    # this dict represents potential relationships to other configuration items
    newcitypes = {
                  'groups': None,
                  'cidrBlockAssociationSet': None,
                  'ipv6CidrBlockAssociationSet': None,
                  'relationships': None,
                  'relatedEvents': None,
                  'rolePolicyList': None,
                  'instanceProfileList': None,
                  'configuration': None,
                  'supplementaryConfiguration': None,
                  'policyVersionList': None,
                  'ipPermissions': None,
                  'ipPermissionsEgress': None,
                  'privateIpAddresses': None,
                  'tags': None}

    # configuration items related to the source configuration item will be stored in this dict
    newcis = {}
    rid = props['resourceId']

    for p in props:
        if p not in newcitypes.keys():
            t = add_property(t, p, props[p])
        else:
            if p == 'relationships':
                for r in props[p]:
                    irid = r['resourceId']
                    if irid is not None:
                        newcis[irid] = (reformat_resource_type(r['resourceType']), r['name'], rid)
            elif p == 'configuration':
                for c in props[p]:
                    if c not in newcitypes.keys():
                        t = add_property(t, c, props[p][c])

    return t, newcis


def mod_config_item(rid, mods):
    for m in mods:
        # delete any relationships specified
        if m.startswith('Relationships.'):
            if mods[m]['changeType'] == 'DELETE':
                delete_relationship(rid, mods[m]['resourceId'], mods[m]['name'])
        else:
            # there maybe other config. item mods we're interested in at a later date, however
            # most changes get propagated to the main configuration item and have already been reflected in the
            # CMDB by now, so there's no need to deal with them here
            pass


def process_config_event(ce):
    rid = ce['configurationItem']['resourceId']
    for centry in ce:
        if centry == 'configurationItem':
            ci = ce[centry]
            cis = ci['configurationItemStatus']
            cit = reformat_resource_type(ci['resourceType'])

            if cis == 'OK':
                # insert the primary configuration item
                rn = ci['resourceName'] if 'resourceName' in ci.keys() and ci['resourceName'] is not None else ''
                t = insert_or_update_config_item(ci['resourceId'], cit, rn)
                # then add its properties
                (t, cis_to_add) = add_properties(ci, t)
                t.next()

                # cis_to_add = { toResourceId, (ciType, relationship, fromResourceId) }
                pp.pprint(cis_to_add)
                for to_rid in cis_to_add.keys():
                    cit = cis_to_add[to_rid][0]
                    relationship = cis_to_add[to_rid][1]
                    from_rid = cis_to_add[to_rid][2]

                    # this will add any configuration items implicitly referenced by the main configuration item event
                    insert_or_update_config_item(to_rid, cit, '').next()
                    insert_or_update_relationship(from_rid, to_rid, relationship).next()
            elif cis == 'ResourceDeleted':
                delete_config_item(rid)
                break
        elif centry == 'configurationItemDiff' and ce[centry] is not None:
            mod_config_item(rid, ce[centry])


def lambda_handler(event, context):
    try:
        # invokingEvent is the item we're actually interested in
        configevent = json.loads(event['invokingEvent'], parse_float=Decimal, object_hook=datetime_parser)
        process_config_event(configevent)

    except Exception:
        traceback.print_exc()
        raise
