#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8
import datetime
import yaml
import logging
from yaml.scanner import ScannerError
import argparse
import ipaddress
from ipaddress import AddressValueError
import sqlite3
from sqlite3 import Error
from urllib.request import pathname2url
from pyzabbix.api import ZabbixAPI
import sys
from pyzabbix import ZabbixMetric, ZabbixSender

#                                       var
db_path = r'zabbix_syslog.db'
format_log = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
path_to_cfg = r'zabbix_sender_syslog_cfg.yaml'
path_to_log = r'file.log'

#                                       Настройки Логирования
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Создаём handlers
c_handler = logging.StreamHandler()
f_handler = logging.FileHandler(path_to_log)
c_handler.setLevel(logging.DEBUG)
f_handler.setLevel(logging.ERROR)
# Создаём форматирование и добавляем его в  handlers
c_format = logging.Formatter(format_log)
f_format = logging.Formatter(format_log)
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)
# Прикручиваем созданный handlers к объекту logger
logger.addHandler(c_handler)
logger.addHandler(f_handler)

#                                         Проверяем доступность файла с настройками
try:
    with open(path_to_cfg) as yamlConfFile:
        confYaml = yaml.safe_load(yamlConfFile)  # Загружаем настройки!!!!!!!
except FileNotFoundError:
    logger.exception('ПАНИКА НЕТ ФАЙЛА С НАСТРОЙКАМИ!!!')
    sys.exit(1)
except PermissionError:
    logger.exception('ПАНИКА НЕТ ДОСТУПА К ФАЙЛУ С НАСТРОЙКАМИ!!!')
    sys.exit(1)
except ImportError:
    logger.exception('ПАНИКА КРИВОЙ Импорт ФАЙЛА С НАСТРОЙКАМИ!!!')
    sys.exit(1)
except ScannerError:
    logger.exception('ПАНИКА КРИВОЙ ФОРМАТ ФАЙЛА С НАСТРОЙКАМИ!!!')
    sys.exit(1)
finally:
    yamlConfFile.close()
#                                    Получаем аргументы скрипта
parser = argparse.ArgumentParser()
# parser.add_argument('--ip', required=True, type=str)
parser.add_argument('msg', type=str, nargs='+')
namespace = parser.parse_args()


########################################
def pars_arg_msg(msg):
    logger.debug(*msg)
    in_ = str(*msg)
    ip = in_[(in_.find('[') + 1):in_.find(']')]
    logger.debug(ip)
    st = in_[0:in_.find('[')] + ' ' + in_[in_.find(']') + 1:]
    logger.debug(st)
    return [ip, st]


def check_ip(try_ip, end_error):
    try:
        ipaddress.ip_address(try_ip)
    except AddressValueError:
        logger.exception('КРИВОЙ IP КЛИЕНТА ' + end_error)
        sys.exit(1)
    except ValueError:
        logger.exception('ВМЕСТО IP ПЕРЕДАНА ЕРУНДА ' + end_error)
        sys.exit(1)


def search_ex_in_dict(dict_, ex_, s_ex_):
    for d in dict_:
        if dict_[d][ex_] == s_ex_:
            return True
    return False


def send_to_zabbix(hostname, msg, conf_yaml):
    packet = [ZabbixMetric(hostname, 'syslog', msg), ]
    logger.debug(packet)
    sender = ZabbixSender(conf_yaml['api']['ip'])
    logger.debug(sender)
    result = sender.send(packet)
    logger.debug(result)
    return None


def get_host_from_db(cur, conf_yaml, node_ip, conn_):
    try:
        with ZabbixAPI(url=conf_yaml['api']['server'], user=conf_yaml['api']['user'],
                       password=conf_yaml['api']['password']) as zabbix_api:
            result2 = zabbix_api.do_request('item.get', dict(output=['itemid'], search=dict(key_="syslog",
                                                                                            type=2, status=0)))
            items = []
            host_node = dict()
            for res in result2['result']:
                items.append(res['itemid'])
            result1 = zabbix_api.do_request('host.get',
                                            dict(itemids=items, output=['hostid', 'host']))
            for res in result1['result']:
                host_node.update({res['hostid']: dict(name=res['host'], ip=None)})
            result3 = zabbix_api.do_request('hostinterface.get',
                                            dict(output=['ip', 'hostid'], hostids=[*host_node.keys()]))
            for res in result3['result']:
                if res['hostid'] in host_node:
                    host_node[res['hostid']]['ip'] = res['ip']
            try:
                if not search_ex_in_dict(host_node, 'ip', node_ip):
                    raise AddressValueError(node_ip)
            except AddressValueError:
                logger.exception('На адресе:::' + node_ip + ':::Не настроен syslog элемент данных в zabbix')
                sys.exit(1)
            for h in host_node:
                ins_sql = (datetime.datetime.now(), h, host_node[h]['ip'], host_node[h]['name'])
                sql_ = """INSERT INTO 'zabbix_hosts' ('update_time','hostid', 'ip', 'hostname')
                             VALUES (?,?,?,?)"""
                cur.execute(sql_, ins_sql)
                conn_.commit()
    except KeyError:
        logger.exception('Ошибка В параметрах конфигурации')
        sys.exit(1)
    return None


def find_host_in_db(cur, ip):
    sqlite_select_query = f"""SELECT hostname FROM 'zabbix_hosts' WHERE ip = '{ip}'"""
    cur.execute(sqlite_select_query)
    rec = cur.fetchall()
    try:
        return str(*rec[0])
    except IndexError:
        logger.warning('Нет соответствия Ip и имени ноды')
        sys.exit()


#######################################

#                                          Тестируем IP

ret = pars_arg_msg(namespace.msg)
check_ip(ret[0], 'ИЗ АРГУМЕНТА СКРИПТА!!!')

#                                          БД
db_uri = 'file:{}?mode=rw'.format(pathname2url(db_path))
conn = None
try:
    conn = sqlite3.connect(db_uri, uri=True)
    cursor = conn.cursor()
    node_name = find_host_in_db(cursor, ret[0])
    if node_name:
        send_to_zabbix(node_name, ret[1], confYaml)
    cursor.close()
except Error:
    logger.info('Нет файла БД Создаём Новый')
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        sql_create_table_query = '''CREATE TABLE zabbix_hosts (
                                     id INTEGER PRIMARY KEY,
                                     update_time timestamp,
                                     hostid TEXT NOT NULL,
                                     ip TEXT NOT NULL,
                                     hostname TEXT NOT NULL);'''
        cursor.execute(sql_create_table_query)
        get_host_from_db(cursor, confYaml, ret[0], conn)
        node_name = find_host_in_db(cursor, ret[1])
        if node_name:
            send_to_zabbix(node_name, ret[1], confYaml)
        cursor.close()
    except Error:
        logger.exception('Не могу создать и подключиться к БД ПАНИКА !!!!')
        sys.exit(1)
    finally:
        if conn:
            conn.close()
finally:
    if conn:
        conn.close()
