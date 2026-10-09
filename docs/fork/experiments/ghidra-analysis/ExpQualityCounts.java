// Print analysis-quality counters after auto-analysis.
// @category REAExperiment

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class ExpQualityCounts extends GhidraScript {
    @Override
    public void run() throws Exception {
        long functions = 0;
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) { fi.next(); functions++; }

        long instructions = 0, computedJumps = 0, computedJumpsResolved = 0;
        InstructionIterator ii = currentProgram.getListing().getInstructions(true);
        while (ii.hasNext()) {
            Instruction insn = ii.next();
            instructions++;
            FlowType flow = insn.getFlowType();
            if (flow.isJump() && flow.isComputed()) {
                computedJumps++;
                int targets = 0;
                for (Reference ref : insn.getReferencesFrom()) {
                    if (ref.getReferenceType().isFlow()) targets++;
                }
                if (targets > 1) computedJumpsResolved++;
            }
        }
        long data = 0;
        var di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) { di.next(); data++; }

        println("EXPCOUNTS functions=" + functions + " instructions=" + instructions +
            " computed_jumps=" + computedJumps + " computed_jumps_multi_target=" + computedJumpsResolved +
            " defined_data=" + data);
    }
}
