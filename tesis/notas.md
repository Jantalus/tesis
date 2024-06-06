# Notas V-Tune
Soporte Intel: https://supporttickets.intel.com/s/?language=en_US

"Cannot locate debugging information for file `/usr/lib/libc.so.6'"

No puedo ejecutar vtune-gui desde root, probablemente hacerlo sirva para 
lidiar con "Outside known module" o "Unknown" en los analisis

Generar un resultado con vtune CLI desde root no se puede abrir en la GUI no-root, por el siguiente error:
Error: 0x40000003 (Unexpected internal error / invalid state)

## Memory Consumption

Observaciones probablemente bloqueantes
- Warning de loggeo del analisis: Cannot locate debugging information for file `/usr/lib/libc.so.6'
- En el analisis bottom-up para el ejemplo "matrix" que proporciona VTune tenemos
17 allocations de Unkown, probablemente atado al tema de la libc
- 

En la seccion "Summary" encontramos a primera vista:
* (De/)Allocation Size; \#Allocations; \#threads
* Top Memory consumption functions
* Collection and Platform info
    + Tamaño del resultado

En la seccion "Bottom Up" tenemos para agrupar por: Function / Call Stack; Process; Thread / Module 
