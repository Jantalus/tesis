// Experimental instruction-level value tracer for the Case 6 workload.
// x86-64 proof of concept: records memory operands after each instruction.

const target = { base: null, size: 0 };
const active = new Set();
const allowedModules = Process.enumerateModules().filter(module =>
    module.name === "study" || module.name.indexOf("libz") !== -1);

function inAllowedModule(address) {
    // The target library may be loaded after the script starts.  Filtering
    // only the initial module snapshot can therefore miss zlib.  The target
    // range check below keeps the callout selective, so follow all modules.
    return true;
}

function findGlobal(name) {
    try { return Module.getGlobalExportByName(name); }
    catch (_) { return null; }
}

function registerValue(context, name) {
    if (!name) return null;
    const value = context[name];
    return value === undefined ? null : ptr(value);
}

function effectiveAddress(context, memory) {
    const value = memory.value;
    if (!value) return null;

    let address = value.base ? registerValue(context, value.base) : ptr(0);
    if (address === null) return null;

    if (value.index) {
        const index = registerValue(context, value.index);
        if (index === null) return null;
        // The current workload uses small x86-64 index values. NativePointer
        // arithmetic is sufficient for this proof of concept.
        address = address.add(index.toUInt32() * (value.scale || 1));
    }
    return address.add(value.disp || 0);
}

function intersects(address, size) {
    if (address === null || target.base === null) return false;
    const end = address.add(size);
    const targetEnd = target.base.add(target.size);
    return address.compare(targetEnd) < 0 && end.compare(target.base) > 0;
}

function readBytes(address, size) {
    try {
        return Array.from(new Uint8Array(address.readByteArray(size)))
            .map(value => value.toString(16).padStart(2, "0")).join("");
    } catch (_) {
        return "<unavailable>";
    }
}

function recordAccess(context, instructionAddress, access, memory) {
    const address = effectiveAddress(context, memory);
    const size = memory.size || 1;
    if (!intersects(address, size)) return;

    console.log(JSON.stringify({
        operation: access,
        instruction: instructionAddress,
        address: address.toString(),
        size: size,
        bytes_after: readBytes(address, size),
        thread: Process.getCurrentThreadId()
    }));
}

function transform(iterator) {
    let instruction;
    while ((instruction = iterator.next()) !== null) {
        iterator.keep();
        if (!inAllowedModule(instruction.address)) continue;
        const operands = instruction.operands || [];
        const memoryOperands = operands.filter(operand => operand.type === "mem");
        for (const operand of memoryOperands) {
            const capturedInstruction = instruction;
            const capturedInstructionAddress = instruction.address.toString();
            const capturedAccess = operand.access === "w" ? "write" :
                operand.access === "rw" ? "readwrite" : "read";
            const capturedOperand = operand;
            iterator.putCallout(context => {
                recordAccess(context, capturedInstructionAddress, capturedAccess,
                             capturedOperand);
            });
        }
    }
}

function followFunction(threadId, destination, size) {
    target.base = ptr(destination);
    target.size = Number(size);
    console.log("TARGET", target.base, target.size, "thread", threadId);
}

function stopFunction(threadId) {
    target.base = null;
    target.size = 0;
}

const main = findGlobal("main");
if (main !== null) {
    Interceptor.attach(main, {
        onEnter() {
            Stalker.follow(this.threadId, { transform });
        }
    });
}

const known = findGlobal("known_writes");
if (known !== null) {
    Interceptor.attach(known, {
        onEnter(args) {
            const capacity = Process.getModuleByName("study") !== null ?
                (getenv("STUDY_CAPACITY") || 64) : 64;
            followFunction(this.threadId, args[0], capacity);
        },
        onLeave() { stopFunction(this.threadId); }
    });
}

const compress2 = findGlobal("compress2");
if (compress2 !== null) {
    Interceptor.attach(compress2, {
        onEnter(args) {
            followFunction(this.threadId, args[0], args[1].readULong());
        },
        onLeave() { stopFunction(this.threadId); }
    });
}

function getenv(name) {
    const fn = new NativeFunction(Module.getGlobalExportByName("getenv"),
                                  "pointer", ["pointer"]);
    const value = fn(Memory.allocUtf8String(name));
    return value.isNull() ? null : parseInt(value.readUtf8String(), 10);
}
