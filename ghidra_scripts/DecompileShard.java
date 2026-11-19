import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileShard extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("usage: DecompileShard <outDir> <shardIndex> <shardCount> [timeoutSec]");
            return;
        }
        String outDir = args[0];
        int shard = Integer.parseInt(args[1]);
        int shards = Integer.parseInt(args[2]);
        int timeout = args.length > 3 ? Integer.parseInt(args[3]) : 90;
        new File(outDir).mkdirs();

        List<Function> all = new ArrayList<Function>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            all.add(it.next());
        }
        Collections.sort(all, new Comparator<Function>() {
            public int compare(Function a, Function b) {
                return a.getEntryPoint().compareTo(b.getEntryPoint());
            }
        });
        println("TOTAL_FUNCTIONS " + all.size() + " shard " + shard + "/" + shards);

        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.setSimplificationStyle("decompile");
        ifc.openProgram(currentProgram);

        File outFile = new File(outDir, String.format("shard_%02d.c", shard));
        BufferedWriter w = new BufferedWriter(new FileWriter(outFile), 1 << 20);
        int done = 0;
        int failed = 0;
        int idx = 0;
        for (Function fn : all) {
            if ((idx % shards) != shard) {
                idx++;
                continue;
            }
            idx++;
            monitor.checkCancelled();
            String name = fn.getName();
            Address entry = fn.getEntryPoint();
            w.write("\n/* ===== " + name + " @ " + entry.toString() + " size=" + fn.getBody().getNumAddresses() + " ===== */\n");
            try {
                DecompileResults res = ifc.decompileFunction(fn, timeout, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    w.write(res.getDecompiledFunction().getC());
                } else {
                    failed++;
                    w.write("/* DECOMPILE_FAILED " + (res == null ? "null" : res.getErrorMessage()) + " */\n");
                }
            } catch (Exception e) {
                failed++;
                w.write("/* EXCEPTION " + e.toString() + " */\n");
            }
            done++;
            if ((done % 100) == 0) {
                println("shard " + shard + " done=" + done + " failed=" + failed);
                w.flush();
            }
        }
        w.close();
        println("SHARD_DONE " + shard + " done=" + done + " failed=" + failed);
    }
}
