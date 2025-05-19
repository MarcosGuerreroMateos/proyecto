from flask import Flask, render_template, request, flash
import mysql.connector
import threading
import socket

app = Flask(__name__)
app.secret_key = '1234'  # Cambia esto por una clave secreta real

def get_db_connection():
    return mysql.connector.connect(
        host="192.168.56.101",
        user="mibuser_mm",
        password="1234",  
        database="mib_mg"
    )

def insert_trap(oid, value, transport):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (oid, value, date_time, transport)
        VALUES (%s, %s, NOW(), %s)
    """, (oid, value, transport))
    conn.commit()
    cursor.close()
    conn.close()

def udp_trap_receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 9162))  # PUERTO ALTO
    print("UDP Trap receiver listening on UDP/9162...")
    while True:
        data, addr = sock.recvfrom(4096)
        # Intenta decodificar como texto, si no, como hex
        try:
            value = data.decode('utf-8')
            print(f"[Trap recibido] Desde {addr} | Mensaje: {value}")
        except Exception:
            value = data.hex()
            print(f"[Trap recibido] Desde {addr} | Bytes hex: {value}")
        insert_trap(str(addr), value, "UDP/9162")

# Solo lanza el hilo si este es el proceso principal (evita doble lanzamiento con el reloader de Flask)
import os
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
    threading.Thread(target=udp_trap_receiver, daemon=True).start()

@app.route("/traps")
def show_traps():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT trap_id, oid, value, date_time, transport FROM notifications ORDER BY date_time DESC")
    traps = cursor.fetchall()
    cursor.close()
    conn.close()

    if len(traps) > 1:
        flash("¡Nuevo trap recibido!")

    return render_template("traps.html", traps=traps)

@app.route("/", methods=["GET"])
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT oid, traduccio_oid FROM oids")
    oid_list = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("index.html", oid_list=oid_list)

@app.route("/snmp", methods=["POST"])
def snmp():
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, nextCmd, setCmd, bulkCmd
    )
    from pysnmp.proto.rfc1902 import Integer, OctetString

    ip = request.form["ip"]
    community = request.form["community"]
    oid = request.form["oid"]
    operation = request.form["operation"]
    value = request.form.get("value")
    value_type = request.form.get("value_type")

    if operation != "bulkwalk" and not oid.endswith(".0"):
        oid += ".0"

    result = []

    try:
        if operation == "get":
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
        elif operation == "next":
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        elif operation == "bulkwalk":
            iterator = bulkCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                0, 10,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        elif operation == "set":
            if value_type == "Integer":
                typed_value = Integer(int(value))
            else:
                typed_value = OctetString(value)
            iterator = setCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(oid), typed_value)
            )
        else:
            result.append("Operació no reconeguda.")
            return render_template("result.html", result=result)

        for response in iterator:
            errorIndication, errorStatus, errorIndex, varBinds = response
            if errorIndication:
                result.append(f"Error: {errorIndication}")
                break
            elif errorStatus:
                result.append(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
                break
            else:
                for varBind in varBinds:
                    result.append(f"{varBind[0]} = {varBind[1]}")
    except Exception as e:
        result.append(f"Excepció: {e}")

    return render_template("result.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, use_reloader=False)