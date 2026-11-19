import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ApplyGoNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: ApplyGoNames <names.txt>");
            return;
        }
        File f = new File(args[0]);
        BufferedReader br = new BufferedReader(new FileReader(f));
        String line;
        int total = 0;
        int created = 0;
        int renamed = 0;
        int failed = 0;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int tab = line.indexOf(9);
            if (tab <= 0) {
                continue;
            }
            String addrStr = line.substring(0, tab).trim();
            String name = line.substring(tab + 1).trim();
            if (name.isEmpty()) {
                continue;
            }
            total++;
            long val;
            try {
                val = Long.parseUnsignedLong(addrStr, 16);
            } catch (NumberFormatException e) {
                failed++;
                continue;
            }
            Address a = toAddr(val);
            if (a == null) {
                failed++;
                continue;
            }
            Function fn = getFunctionAt(a);
            if (fn == null) {
                fn = getFunctionContaining(a);
                if (fn != null && !fn.getEntryPoint().equals(a)) {
                    fn = null;
                }
            }
            if (fn == null) {
                try {
                    fn = createFunction(a, name);
                } catch (Exception e) {
                    fn = null;
                }
                if (fn != null) {
                    created++;
                }
            }
            if (fn != null) {
                try {
                    fn.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    renamed++;
                } catch (Exception e) {
                    failed++;
                }
            } else {
                failed++;
            }
            if ((total % 500) == 0) {
                println("progress " + total + " created=" + created + " renamed=" + renamed + " failed=" + failed);
            }
        }
        br.close();
        println("APPLY_NAMES total=" + total + " created=" + created + " renamed=" + renamed + " failed=" + failed);
    }
}
