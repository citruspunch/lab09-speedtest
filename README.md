# CC8 Lab 09: Speedtest con raw sockets TCP

Benchmark de red escrito en C para medir latencia y velocidad de transferencia TCP usando sockets raw, con ensamblado manual de paquetes IPv4 y TCP.

## 1. Objetivos

- Construcción manual de cabeceras IPv4 y segmentos TCP con banderas SYN, ACK, PSH y FIN.
- Cálculo de checksums de Internet (RFC 793) y pseudo-header TCP.
- Medición de latencia ICMP directa desde C sin dependencias de comandos externos.
- Establecimiento de sesión TCP mediante handshake de tres vías.
- Transmisión de un archivo de 1 KB (1024 bytes) repetido 10 veces consecutivas sobre la misma conexión TCP.
- Registro del RTT por envío y evaluación de velocidad bajo tres modelos de throughput.

## 2. Modelos de cálculo de velocidad

La prueba transmite 10 iteraciones consecutivas del archivo de 1 KB sobre una única conexión TCP establecida. Para analizar el rendimiento, el benchmark evalúa tres modelos de velocidad:

### 2.1 Variante A: modelo con costo de conexión por envío (2 x RTT)

Este modelo calcula el tiempo de ciclo sumando el establecimiento de conexión y el tiempo de transmisión:

$$\text{Total Time} = \text{RTT} + (\text{RTT} + \text{transmit time}) \approx 2 \times \text{RTT}$$

En enlaces de red rápidos, el tiempo de transmisión de 1 KB es despreciable frente al RTT ($T_{\text{trans}} \approx 0$). La velocidad resulta en:

$$\text{Speed} = \frac{\text{windowSize}}{\sim\text{RTT}} = \frac{1000 \times 8}{2 \times \text{RTT}}$$

Para un RTT de referencia de 32 ms:

$$\text{Speed} = \frac{1000 \times 8}{2 \times 0.032} = \frac{8000}{0.064} = 125\text{ kbps}$$

Este cálculo representa el escenario donde cada archivo asume el costo completo de un ciclo de conexión adicional.

### 2.2 Variante B: modelo de conexión persistente (1 x RTT)

Al transmitir los 10 archivos sobre la misma sesión TCP, el handshake ocurre solo una vez al inicio. Los envíos posteriores únicamente incurren en el viaje de ida y vuelta de datos y su confirmación:

$$\text{Tiempo por envío} = \text{RTT} + T_{\text{trans}}$$

Con un payload de 1 KB (1024 bytes), $T_{\text{trans}}$ tiende a cero frente al RTT en loopback o red local. El tiempo por envío es aproximadamente 1 x RTT:

$$\text{Speed}_{\text{persistente}} = \frac{\text{windowSize}}{1 \times \text{RTT}} = \frac{1000 \times 8}{1 \times \text{RTT}}$$

Para el mismo RTT de 32 ms:

$$\text{Speed}_{\text{persistente}} = \frac{1000 \times 8}{1 \times 0.032} = 250\text{ kbps}$$

Esta variante refleja la tasa esperada en un canal ya establecido al amortizar el handshake en múltiples transferencias.

### 2.3 Variante C: throughput real medido (wall-clock)

Registra la tasa efectiva observada por el reloj del sistema de inicio a fin para los 10 envíos completos:

$$\text{Throughput} = \frac{\text{bytes transmitidos} \times 8}{\text{tiempo total (s)}} = \frac{10240 \times 8}{\text{tiempo transcurrido (s)}}$$

Esta métrica incluye los tiempos del kernel, procesamiento del socket receptor, confirmaciones TCP y pausas entre paquetes.

## 3. Estructura del proyecto

```
lab09-speedtest/
├── Makefile                 # Reglas de compilación para macOS y Linux
├── README.md                # Documentación del proyecto
├── .gitignore               # Exclusiones de Git
├── run_speedtest.sh         # Script de ejecución con tcpdump y firewall
├── assets/
│   └── 1kb-image            # Archivo de prueba de 1024 bytes (1 KB)
├── include/
│   ├── checksum.h           # Declaraciones de checksum IPv4 y TCP
│   ├── ip_header.h          # Estructura y constructor IPv4
│   ├── tcp_header.h         # Estructura y constructor TCP
│   ├── raw_socket.h         # Abstracción de sockets raw (macOS pcap / Linux)
│   ├── ping.h               # Medición de latencia ICMP
│   ├── logger.h             # Salida formateada de segmentos TCP
│   └── speedtest.h          # Métricas y control de sesión
└── src/
    ├── checksum.c           # Checksum de complemento a 1
    ├── ip_header.c          # Constructor IPv4 (maneja orden BSD vs Linux)
    ├── tcp_header.c         # Constructor de segmentos TCP
    ├── raw_socket.c         # Envío raw y captura de paquetes
    ├── ping.c               # Ping ICMP nativo
    ├── logger.c             # Formateo y volcado de paquetes
    ├── speedtest_client.c   # Cliente de prueba con sockets raw
    └── speedtest_server.c   # Servidor receptor en C
```

## 4. Requisitos del sistema

- Compilador C99 o C11 (gcc o clang).
- Herramientas del sistema: make y tcpdump.
- macOS (requiere libpcap y pfctl) o Linux (requiere AF_INET SOCK_RAW e iptables).
- Privilegios de administrador (sudo) para abrir sockets raw y capturar paquetes.

## 5. Compilación

Compilar cliente y servidor:

```bash
make
```

Limpiar ejecutables y archivos temporales:

```bash
make clean
```

Empaquetar el archivo zip para entrega:

```bash
make zip
```

## 6. Ejecución

### Opción A: ejecución automatizada

El script `run_speedtest.sh` ejecuta la secuencia completa:
1. Compila los binarios en C.
2. Configura una regla de firewall temporal (pf en macOS o iptables en Linux) para que el kernel no emita paquetes RST al recibir tráfico en puertos efímeros raw.
3. Inicia el servidor `speedtest_server` en segundo plano en el puerto 5001.
4. Inicia tcpdump en segundo plano hacia `speedtest.pcap`.
5. Ejecuta `speedtest_client` con sudo, guardando el registro en `speedtest.log`.
6. Detiene tcpdump, muestra el resumen de paquetes capturados y restaura el estado original del firewall.

```bash
./run_speedtest.sh
```

Opciones disponibles:
- `-p <puerto>`: Puerto TCP de destino (default: 5001).
- `-i <interfaz>`: Interfaz de red (default: `lo0` en macOS, `lo` en Linux).
- `--keep-server`: Mantiene el servidor en ejecución al terminar.

### Opción B: ejecución manual

#### 1. Suprimir RST automático del kernel

En macOS:
```bash
echo 'block drop out proto tcp from any port 40000:49999 flags R/R' | sudo pfctl -f -
sudo pfctl -e
```

En Linux:
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP
```

#### 2. Iniciar el servidor (Terminal 1)
```bash
./build/speedtest_server -p 5001
```

#### 3. Iniciar tcpdump (Terminal 2)
```bash
sudo tcpdump -i lo0 -nn "tcp port 5001"
```

#### 4. Ejecutar el cliente (Terminal 3)
```bash
sudo ./build/speedtest_client -l 127.0.0.1 -s 127.0.0.1 -p 5001 -f assets/1kb-image -i lo0
```

#### 5. Restaurar firewall al finalizar

En macOS:
```bash
sudo pfctl -f /etc/pf.conf
```

En Linux:
```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport 40000:49999 -j DROP
```

## 7. Flujo de paquetes TCP

Durante la prueba, tcpdump registra el siguiente intercambio:

```text
1. Handshake TCP (3-way):
   Client -> Server  [SYN]      SEQ=X ACK=0
   Server -> Client  [SYN, ACK] SEQ=Y ACK=X+1    <-- RTT de handshake
   Client -> Server  [ACK]      SEQ=X+1 ACK=Y+1

2. Transmisión del archivo (10 envíos sobre el mismo canal):
   Para cada archivo i (1..10):
     Client -> Server  [PSH, ACK] SEQ=X_i ACK=Y_i LEN=1024 DATA=(1 KB payload)
     Server -> Client  [PSH, ACK] SEQ=Y_i ACK=X_i+1024 LEN=4 DATA="ACK\n"  <-- RTT del envio
     Client -> Server  [ACK]      SEQ=X_i+1024 ACK=Y_i+4

3. Cierre de conexión:
   Client -> Server  [FIN, ACK] SEQ=Final ACK=Final
   Server -> Client  [ACK]      SEQ=... ACK=Final+1
   Server -> Client  [FIN, ACK] SEQ=... ACK=Final+1
   Client -> Server  [ACK]      SEQ=Final+1 ACK=Server_Fin+1
```

## 8. Formato de salida del cliente

```text
======================================================================
                    SPEEDTEST PERFORMANCE SUMMARY                     
======================================================================
 [STAGE 1] Latency Measurement (ICMP Ping)
   * Measured Ping Latency:                0.180 ms
----------------------------------------------------------------------
 [STAGE 2] TCP RAW Connection & Transmission
   * Initial TCP Handshake RTT:            0.850 ms  (SYN -> SYN+ACK)
   * Payload per Transfer:                  1024 bytes (1 KB)
   * Transfers Completed:                     10 transfers
   * Total Bytes Transmitted:              10240 bytes
   * Transfer RTT (Average):               0.435 ms
   * Total Wall-Clock Elapsed Time:      115.200 ms
----------------------------------------------------------------------
 [STAGE 3] Speed Calculations & Throughput Variants
   * Formula: Total Time = RTT + (RTT + transmit time)
     Total Cycle Time:                     1.285 ms  (Initial RTT + Avg Transfer RTT)
     Assumed Cycle (2 * Avg RTT):          0.870 ms

 [VARIANTE A] Modelo con Costo de Conexion por Envio (2 x RTT):
   * Supuesto: Cada envio asume RTT_handshake + (RTT + T_trans) ~= 2 * RTT
     - Con 1000 Bytes: (1000 * 8) / (2 * 0.000435 s) =    9195.40 kbps (  9.20 Mbps)
     - Con 1024 Bytes: (1024 * 8) / (2 * 0.000435 s) =    9416.09 kbps (  9.42 Mbps)

 [VARIANTE B] Conexion Persistente / Misma Conexion TCP (Modelo 1 x RTT):
   * Supuesto: Handshake unico inicial; cada envio es RTT + T_trans ~= 1 * RTT (T_trans ~= 0)
     - Con 1000 Bytes: (1000 * 8) / (1 * 0.000435 s) =   18390.80 kbps ( 18.39 Mbps)
     - Con 1024 Bytes: (1024 * 8) / (1 * 0.000435 s) =   18832.18 kbps ( 18.83 Mbps)

 [VARIANTE C] Rendimiento Efectivo Empirico (Throughput Real Wall-Clock):
   * Supuesto: Medicion real del tiempo total transcurrido para los 10 archivos
     - Throughput:     (10240 * 8) / (0.115200 s) =     711.11 kbps (  0.71 Mbps)
======================================================================
```
