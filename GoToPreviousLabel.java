//Go to the previous label before the current address
//@author Christoph Brill <opensource@christophbrill.de>
//@category Search
//@keybinding
//@menupath Go to Previous Label
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class GoToPreviousLabel extends GhidraScript {

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

        Address programMin = currentProgram.getMinAddress();
        if (programMin == null) {
            printerr("Program has no minimum address.");
            return;
        }

        Address targetBefore = currentAddress.previous();
        if (targetBefore == null) {
            printerr("No previous address exists before current address: " + currentAddress);
            return;
        }

        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getSymbolIterator(programMin, true);

        Address lastLabel = null;
        while (it.hasNext() && !monitor.isCancelled()) {
            Symbol s = it.next();
            if (s == null) {
                continue;
            }
            if (s.getSymbolType() != SymbolType.LABEL) {
                continue;
            }

            Address a = s.getAddress();
            if (a == null) {
                continue;
            }

            if (a.compareTo(currentAddress) >= 0) {
                break;
            }

            lastLabel = a;
        }

        if (monitor.isCancelled()) {
            return;
        }

        if (lastLabel == null) {
            printerr("No previous label found before " + currentAddress);
            return;
        }

        goTo(lastLabel);
        currentAddress = lastLabel;
    }
}
