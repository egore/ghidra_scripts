//If current address is a default string label (s_<...>_<addr>), rename it to the full string in quotes
//@author Christoph Brill <opensource@christophbrill.de>
//@category Data Types
//@keybinding Shift-L
//@menupath Label Default String With Quotes
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class LabelDefaultStringWithQuotes extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No active program.");
            return;
        }
        if (currentAddress == null) {
            printerr("No current address (place the cursor in the Listing view and re-run).");
            return;
        }

        Address addr = currentAddress;
        Listing listing = currentProgram.getListing();
        Data d = listing.getDataAt(addr);
        if (d == null) {
            printerr("No data at current address: %s".formatted(addr));
            return;
        }

        Object value = d.getValue();
        if (!(value instanceof String s)) {
            printerr("Data at %s is not a string (expected ds/string data). Found: %s".formatted(addr, d.getDataType().getName()));
            return;
        }

        SymbolTable st = currentProgram.getSymbolTable();
        Symbol sym = st.getPrimarySymbol(addr);
        if (sym == null) {
            printerr("No primary symbol at %s".formatted(addr));
            return;
        }

        // Ghidra does not allow blanks in labels, use underscores instead
        String cleaned = s.replace(" ", "_")
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
        String newName = "\"" + cleaned + "\"";
        println(s);
        println(newName);

        String oldName = sym.getName();

        if (!oldName.equals(newName)) {
            String addrSuffix = "_" + addr;
            if (!oldName.startsWith("s_") || !oldName.endsWith(addrSuffix)) {
                printerr("Primary symbol name does not look like a default string label: %s".formatted(oldName));
                return;
            }

            if (sym.getSource() != SourceType.DEFAULT) {
                printerr("Primary symbol at %s is not DEFAULT-sourced (won't change): %s".formatted(addr, oldName));
                return;
            }

            try {
                sym.setName(newName, SourceType.USER_DEFINED);
                println("Renamed %s -> %s at %s".formatted(oldName, newName, addr));
            } catch (Exception e) {
                printerr("Failed to rename label at %s to '%s': %s".formatted(addr, newName, e.getMessage()));
            }
        } else {
            println("Label already matches desired name: %s".formatted(newName));
        }

        // Jump no address after the string, which likely is the next string
        Address next = d.getMaxAddress().next();
        if (next != null) {
            goTo(next);
            currentAddress = next;
        }

    }
}
