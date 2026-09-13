// Frida page-access baseline for case 6.
// Run with: frida -f ./study -l frida_monitor.js --no-pause

const getenv = new NativeFunction(Module.getGlobalExportByName("getenv"),
                                  "pointer", ["pointer"]);
const capacityPointer = getenv(Memory.allocUtf8String("STUDY_CAPACITY"));
const configuredCapacity = capacityPointer.isNull()
    ? 8192
    : parseInt(capacityPointer.readUtf8String(), 10);

function monitor(name, destination, size) {
  console.log("TARGET", name, destination, size);
  MemoryAccessMonitor.enable({ base: destination, size: size }, {
    onAccess(details) {
      console.log("ACCESS", details.operation, details.address,
                  details.from, details.threadId, details.pageIndex);
    }
  });
}

function findGlobal(name) {
  try { return Module.getGlobalExportByName(name); }
  catch (_) { return null; }
}

const known = findGlobal("known_writes");
if (known !== null) {
  Interceptor.attach(known, {
    onEnter(args) { monitor("known_writes", args[0], configuredCapacity); },
    onLeave() { MemoryAccessMonitor.disable(); }
  });
}

const compress2 = findGlobal("compress2");
if (compress2 !== null) {
  Interceptor.attach(compress2, {
    onEnter(args) {
      const size = args[1].readULong();
      monitor("compress2", args[0], size);
    },
    onLeave() { MemoryAccessMonitor.disable(); }
  });
}
