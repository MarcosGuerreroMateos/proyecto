from flask import Flask, render_template, request

from pysnmp import *

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])
def index():
    result = None  # Inicializamos el resultado para evitar errores

    if request.method == "POST":
        # Recuperamos los datos del formulario
        agent_ip = request.form['agent_ip']
        snmp_version = request.form['snmp_version']
        community = request.form['community']
        oid = request.form['oid']
        operation = request.form['operation']

        # Añadimos ".0" al OID si es necesario (excepto para SNMPBULKWALK)
        if operation != "SNMPBULKWALK" and not oid.endswith('.0'):
            oid += '.0'

        # Definir la versión SNMP
        snmp_version = 0 if snmp_version == 'v1' else 1  # v1=0, v2c=1

        try:
            # SNMPGET
            if operation == "SNMPGET":
                print(f"Realizando SNMPGET al agente {agent_ip}, versión {snmp_version}, comunidad '{community}', OID {oid}")
                iterator = get_cmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version),
                    UdpTransportTarget((agent_ip, 161), timeout=5, retries=3),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

                if errorIndication:
                    print(f"Error de SNMPGET: {errorIndication}")
                    result = f"Error: {errorIndication}"
                elif errorStatus:
                    print(f"Error de estado: {errorStatus.prettyPrint()}")
                    result = f"Error: {errorStatus.prettyPrint()}"
                else:
                    for varBind in varBinds:
                        print(f"Resultado SNMPGET: {varBind[0]} = {varBind[1]}")
                        result = f"{varBind[0]} = {varBind[1]}"

            # SNMPNEXT
            elif operation == "SNMPNEXT":
                iterator = next_cmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version),
                    UdpTransportTarget((agent_ip, 161), timeout=5, retries=3),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

                if errorIndication:
                    result = f"Error: {errorIndication}"
                elif errorStatus:
                    result = f"Error: {errorStatus.prettyPrint()}"
                else:
                    for varBind in varBinds:
                        result = f"{varBind[0]} = {varBind[1]}"

            # SNMPSET
            elif operation == "SNMPSET":
                iterator = set_cmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version),
                    UdpTransportTarget((agent_ip, 161), timeout=5, retries=3),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid), 42)  # Establecemos un valor ficticio (42) como ejemplo
                )
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

                if errorIndication:
                    result = f"Error: {errorIndication}"
                elif errorStatus:
                    result = f"Error: {errorStatus.prettyPrint()}"
                else:
                    result = "SNMPSET exitoso"

            # SNMPBULKWALK
            elif operation == "SNMPBULKWALK":
                iterator = bulk_cmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=snmp_version),
                    UdpTransportTarget((agent_ip, 161), timeout=5, retries=3),
                    ContextData(),
                    0, 25,  # Non-repeaters, Max-repetitions
                    ObjectType(ObjectIdentity(oid))
                )
                result_list = []
                for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                    if errorIndication:
                        result = f"Error: {errorIndication}"
                        break
                    elif errorStatus:
                        result = f"Error: {errorStatus.prettyPrint()}"
                        break
                    else:
                        for varBind in varBinds:
                            result_list.append(f"{varBind[0]} = {varBind[1]}")
                if not result:
                    result = "\n".join(result_list)

        except Exception as e:
            result = f"Error ejecutando SNMP: {e}"

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)