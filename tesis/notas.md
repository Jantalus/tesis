EL FIN DE MOMENTO ES CONSEGUIR (automaticamente?) LA TRAZA DE ACCESO A MEMORIA DE CIERTAS VARIABLES
"ciertas variables" siendo seguramente las mas grandes

# Notas V-Tune
Soporte Intel: https://supporttickets.intel.com/s/?language=en_US

"Cannot locate debugging information for file `/usr/lib/libc.so.6'"
¿Bloqueante?

No puedo ejecutar vtune-gui desde root, probablemente hacerlo sirva para 
lidiar con "Outside known module" o "Unknown" en los analisis

Generar un resultado con vtune CLI desde root no se puede abrir en la GUI no-root, por el siguiente error:
Error: 0x40000003 (Unexpected internal error / invalid state)
En cambio generar un reporte con vtune CLI desde no-root y leer el reporte desde la GUI no-root esta OK,
pero no lidia con los problemas de los "uknown" que *CREERIA* que va porque vtune corre en no-root y 
el kernel oculta informacion de los modules.

## Memory Consumption
Aparentemente no provee muchas opciones mas que "minimal dynamic memory object size to track"


En la seccion "Summary" encontramos a primera vista:
* (De/)Allocation Size; \#Allocations; \#threads
* Top Memory consumption functions
* Collection and Platform info
    + Tamaño del resultado

En la seccion "Bottom Up" tenemos para agrupar por: Function / Call Stack; Process; Thread / Module; y varias mas
Haciendo doble click nos lleva (no siempre puede) al source file donde se reserva la cantidad de memoria que indica
la fila de esta seccion

### Observaciones probablemente bloqueantes
- Warning de loggeo del analisis: Cannot locate debugging information for file `/usr/lib/libc.so.6'
- En el analisis bottom-up para el ejemplo "matrix" que proporciona VTune tenemos
17 allocations de Unkown, probablemente atado al tema de la libc y/o permisos de kernel
- 

## Memory Access
¿Nada sobre las trazas de memoria?

Data sobre las opciones del analisis: 
https://www.intel.com/content/www/us/en/docs/vtune-profiler/user-guide/2023-1/memory-access-analysis.html

Opcion de "Analyze dynamic memory objects":
Enable the instrumentation of dynamic memory allocation/de-allocation and map hardware events to such 
memory objects. This option may cause additional runtime overhead due to the instrumentation of all 
system memory allocation/de-allocation API.
Probablemente si realizamos este analisis quisieramos esta opcion prendida


En "Summary" se encuentra 
- Diagrama de accesso a memoria: la interaccion de DRAM con el socket del core (?)
- Avg de utilizacion de la banda ancha de memoria
- Tamaño del resultado 

En "Bottom-up"
En principio como para Memory Consumption Analysis tenemos varias formas de agrupar la informacion del reporte 
ademas de algunas nuevas como por "Bandwidth domain"; "Bandwidth utilization type"; "Open MP region" ¿?; "Cache line"


