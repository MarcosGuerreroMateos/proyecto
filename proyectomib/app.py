from flask import Flask, render_template, request
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    setCmd,
    bulkCmd
)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/snmp', methods=['POST'])
def snmp_operation():
    agent = request.form['agent']
    version = request.form['version']
    community = request.form['community']
    oid = request.form['oid']
    operation = request.form['operation']

    # Asegurarse de que el OID tiene .0 al final si es escalar
    if operation in ['get', 'set', 'next'] and not oid.endswith('.0'):
        oid += '.0'

    result = "Operación no implementada todavía."

    if operation == 'get':
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if version == 'v1' else 1),
                UdpTransportTarget((agent, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                result = f"Error: {errorIndication}"
            elif errorStatus:
                result = f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            else:
                result = ' - '.join([f"{name.prettyPrint()} = {val.prettyPrint()}" for name, val in varBinds])
        except Exception as e:
            result = f"Error ejecutando SNMP: {e}"

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
