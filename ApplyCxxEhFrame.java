// Retypes the MSVC C++ EH prolog (push -1; push handler; push fs:[0]) as a CxxEhFrame struct.
// With a listing selection it processes every function in the selection, otherwise the function under the cursor.
//@category C++
//@keybinding shift X
//@menupath Tools.Apply C++ EH Frame

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;

public class ApplyCxxEhFrame extends GhidraScript {

	private static final int FRAME_SIZE = 12;
	private static final int PROLOG_SCAN_LIMIT = 24;

	@Override
	protected void run() throws Exception {
		List<Function> targets = new ArrayList<>();
		if (currentSelection != null && !currentSelection.isEmpty()) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(currentSelection, true)) {
				targets.add(f);
			}
		}
		else {
			Function f = currentAddress == null ? null : getFunctionContaining(currentAddress);
			if (f == null) {
				popup("Place the cursor inside a function or select a range first.");
				return;
			}
			targets.add(f);
		}

		DataType frameType = getOrCreateFrameType();
		int applied = 0;
		for (Function f : targets) {
			monitor.checkCancelled();
			if (apply(f, frameType)) {
				applied++;
			}
		}
		println("CxxEhFrame applied to " + applied + " of " + targets.size() + " function(s)");
	}

	private DataType getOrCreateFrameType() {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataType existing = dtm.getDataType(CategoryPath.ROOT, "CxxEhFrame");
		if (existing != null) {
			return existing;
		}
		StructureDataType s = new StructureDataType("CxxEhFrame", 0);
		s.add(new Pointer32DataType(), 4, "prev", "saved ExceptionList (fs:[0])");
		s.add(new Pointer32DataType(), 4, "handler", "frame handler stub");
		s.add(IntegerDataType.dataType, 4, "state", "try level, -1 = outside any try");
		return dtm.resolve(s, DataTypeConflictHandler.KEEP_HANDLER);
	}

	private boolean apply(Function f, DataType frameType) throws Exception {
		Instruction pushState = null;
		Instruction pushHandler = null;

		Instruction in = getInstructionAt(f.getEntryPoint());
		for (int i = 0; in != null && i < PROLOG_SCAN_LIMIT; i++, in = in.getNext()) {
			if (in.getFlowType().isCall()) {
				break;
			}
			if (!isPushImm(in)) {
				continue;
			}
			Scalar s = in.getScalar(0);
			if (s.getSignedValue() != -1) {
				continue;
			}
			Instruction handlerPush = findHandlerPush(in);
			if (handlerPush != null) {
				pushState = in;
				pushHandler = handlerPush;
				break;
			}
		}
		if (pushState == null) {
			println("  " + f.getName() + ": no EH prolog found");
			return false;
		}

		int depth = depthBefore(f, pushState);
		if (depth == Integer.MIN_VALUE) {
			println("  " + f.getName() + ": cannot track stack pointer before EH prolog, skipped");
			return false;
		}

		// state is pushed first (highest address), prev last (lowest), so the struct starts 12 below it
		int start = depth - FRAME_SIZE;

		StackFrame sf = f.getStackFrame();
		for (Variable v : sf.getStackVariables()) {
			int off = v.getStackOffset();
			boolean overlaps = off < start + FRAME_SIZE && off + v.getLength() > start;
			if (overlaps || v.getName().equals("ehFrame")) {
				f.removeVariable(v);
			}
		}
		sf.createVariable("ehFrame", start, frameType, SourceType.USER_DEFINED);

		renameHandler(f, pushHandler.getScalar(0));
		return true;
	}

	// Ghidra's depth-analysis class moved between versions, so track ESP over the few prolog instructions by hand.
	private int depthBefore(Function f, Instruction target) {
		int depth = 0;
		Instruction in = getInstructionAt(f.getEntryPoint());
		while (in != null && !in.getAddress().equals(target.getAddress())) {
			String mn = in.getMnemonicString().toUpperCase();
			if (mn.equals("PUSH")) {
				depth -= 4;
			}
			else if (mn.equals("SUB") && in.getRegister(0) != null && in.getRegister(0).getName().equals("ESP")) {
				Scalar s = in.getScalar(1);
				if (s == null) {
					return Integer.MIN_VALUE;
				}
				depth -= (int) s.getSignedValue();
			}
			else if (mn.equals("AND") && in.getRegister(0) != null && in.getRegister(0).getName().equals("ESP")) {
				// stack realignment: Ghidra's decompiler folds this into the offsets by masking the tracked depth
				Scalar s = in.getScalar(1);
				if (s == null) {
					return Integer.MIN_VALUE;
				}
				depth &= (int) s.getSignedValue();
			}
			else if (mn.equals("PUSHAD") || mn.equals("PUSHFD") || mn.equals("POP") || mn.equals("ADD") && in.getRegister(0) != null && in.getRegister(0).getName().equals("ESP")) {
				return Integer.MIN_VALUE;
			}
			in = in.getNext();
		}
		return in == null ? Integer.MIN_VALUE : depth;
	}

	private boolean isPushImm(Instruction in) {
		return "PUSH".equalsIgnoreCase(in.getMnemonicString()) && in.getNumOperands() == 1 &&
			in.getScalar(0) != null;
	}

	// MSVC schedules the fs:[0] load either before or after the handler push, so accept both orders
	// within a short window after push -1. Returns the handler push, or null if this isn't an EH prolog.
	private Instruction findHandlerPush(Instruction pushState) {
		Instruction handlerPush = null;
		boolean readsFs = false;
		Instruction in = pushState.getNext();
		for (int i = 0; in != null && i < 5 && !in.getFlowType().isCall(); i++, in = in.getNext()) {
			if (handlerPush == null && isPushImm(in)) {
				handlerPush = in;
			}
			if (in.toString().toUpperCase().contains("FS:")) {
				readsFs = true;
			}
		}
		return readsFs ? handlerPush : null;
	}

	private void renameHandler(Function owner, Scalar handlerValue) throws Exception {
		Address addr = toAddr(handlerValue.getUnsignedValue());
		Function handler = getFunctionAt(addr);
		if (handler == null) {
			// Ghidra often only labels the stub (LAB_...) because nothing calls it directly
			if (getInstructionAt(addr) == null) {
				disassemble(addr);
			}
			if (getInstructionAt(addr) == null) {
				println("  " + owner.getName() + ": cannot disassemble handler at " + addr);
				return;
			}
			handler = createFunction(addr, null);
			if (handler == null) {
				println("  " + owner.getName() + ": could not create handler function at " + addr);
				return;
			}
			println("  " + owner.getName() + ": created handler function at " + addr);
		}
		if (!handler.getName().startsWith("FUN_")) {
			return;
		}
		String base = "EH_Handler_" + owner.getName();
		try {
			handler.setName(base, SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException e) {
			handler.setName(base + "_" + owner.getEntryPoint(), SourceType.USER_DEFINED);
		}
	}
}
