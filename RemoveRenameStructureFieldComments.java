//Remove "Created by Rename Structure Field action" comments from user-defined structure fields
//@author Christoph Brill <opensource@christophbrill.de>
//@category Data Types
//@keybinding
//@menupath Data Types.Remove Rename Structure Field Comments
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.SourceArchive;

import java.util.Iterator;

public class RemoveRenameStructureFieldComments extends GhidraScript {

    private static final String TARGET_COMMENT = "Created by Rename Structure Field action";

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No active program.");
            return;
        }

        boolean dryRun = askYesNo("Dry-run?", "If YES, no changes are written; the script will only report what it would change.");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        SourceArchive localArchive = dtm.getLocalSourceArchive();
        String localArchiveId = localArchive != null && localArchive.getSourceArchiveID() != null ? localArchive.getSourceArchiveID().toString() : null;

        long scannedStructs = 0;
        long skippedArchiveStructs = 0;
        long scannedFields = 0;
        long clearedFieldComments = 0;
        long modifiedStructs = 0;

        int tx = currentProgram.startTransaction("Remove Rename Structure Field Comments");
        boolean commit = false;
        try {
            Iterator<DataType> it = dtm.getAllDataTypes();
            while (it.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }

                DataType dt = it.next();
                if (!(dt instanceof Structure s)) {
                    continue;
                }

                scannedStructs++;

                if (isFromNonLocalArchive(s, localArchiveId)) {
                    skippedArchiveStructs++;
                    continue;
                }

                boolean structModified = false;

                DataTypeComponent[] comps = s.getComponents();
                for (DataTypeComponent c : comps) {
                    if (monitor.isCancelled()) {
                        break;
                    }
                    if (c == null) {
                        continue;
                    }

                    scannedFields++;
                    String comment = c.getComment();
                    if (comment == null) {
                        continue;
                    }

                    if (TARGET_COMMENT.equals(comment)) {
                        clearedFieldComments++;
                        structModified = true;
                        if (!dryRun) {
                            c.setComment(null);
                        }
                    }
                }

                if (structModified) {
                    modifiedStructs++;
                }
            }

            commit = !dryRun;
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        println("Done.");
        println("Scanned structures: %d".formatted(scannedStructs));
        println("Skipped archive-derived structures: %d".formatted(skippedArchiveStructs));
        println("Scanned fields: %d".formatted(scannedFields));
        println("Structures with matching comments: %d".formatted(modifiedStructs));
        println("Field comments removed: %d".formatted(clearedFieldComments));
        if (dryRun) {
            println("Dry-run was enabled; no changes were committed.");
        }
    }

    private boolean isFromNonLocalArchive(DataType dt, String localArchiveId) {
        if (dt == null) {
            return false;
        }

        SourceArchive sa = dt.getSourceArchive();
        if (sa == null || sa.getSourceArchiveID() == null) {
            return false;
        }

        if (localArchiveId == null) {
            return true;
        }

        return !localArchiveId.equals(sa.getSourceArchiveID().toString());
    }
}
