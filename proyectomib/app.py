from flask import Flask, render_template, request
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd, setCmd
)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/snmp', methods=['POST'])
def snmp_operation():
    try:
        # Captura de datos desde el formulario
        operation = request.form.get('operation')
        agent_ip = request.form.get('agent_ip')
        community = request.form.get('community')
        oid = request.form.get('oid')

        # Agregar '.0' al OID si es necesario
        if operation in ['SNMPGET', 'SNMPNEXT', 'SNMPSET'] and not oid.endswith('.0'):
            oid = f"{oid}.0"

        # Ejecutar la operación SNMP correspondiente
        result = None
        if operation == 'SNMPGET':
            result = snmp_get(agent_ip, community, oid)
        elif operation == 'SNMPNEXT':
            result = snmp_next(agent_ip, community, oid)
        elif operation == 'SNMPBULKWALK':
            result = snmp_bulkwalk(agent_ip, community, oid)
        elif operation == 'SNMPSET':
            value = request.form.get('value')
            result = snmp_set(agent_ip, community, oid, value)

        return render_template('resultat.html', result=result)

    except Exception as e:
        return render_template('resultat.html', result=f"Error: {e}")

# Función para SNMPGET
def snmp_get(agent_ip, community, oid):
    for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((agent_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    ):
        if errorIndication:
            return f"Error: {errorIndication}"
        elif errorStatus:
            return f"Error: {errorStatus.prettyPrint()}"
        else:
            return f"{varBinds[0].prettyPrint()}"

# Función para SNMPNEXT
def snmp_next(agent_ip, community, oid):
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((agent_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    ):
        if errorIndication:
            return f"Error: {errorIndication}"
        elif errorStatus:
            return f"Error: {errorStatus.prettyPrint()}"
        else:
            return f"{varBinds[0].prettyPrint()}"

# Función para SNMPBULKWALK
def snmp_bulkwalk(agent_ip, community, oid):
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in bulkCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((agent_ip, 161)),
        ContextData(),
        0, 25,  # Non-repeaters, max-repetitions
        ObjectType(ObjectIdentity(oid))
    ):
        if errorIndication:
            return f"Error: {errorIndication}"
        elif errorStatus:
            return f"Error: {errorStatus.prettyPrint()}"
        else:
            results.append(f"{varBinds[0].prettyPrint()}")
    return '\n'.join(results)

# Función para SNMPSET
def snmp_set(agent_ip, community, oid, value):
    for (errorIndication, errorStatus, errorIndex, varBinds) in setCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((agent_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid), value)
    ):
        if errorIndication:
            return f"Error: {errorIndication}"
        elif errorStatus:
            return f"Error: {errorStatus.prettyPrint()}"
        else:
            return f"{varBinds[0].prettyPrint()}"

if __name__ == '__main__':
    app.run(debug=True)