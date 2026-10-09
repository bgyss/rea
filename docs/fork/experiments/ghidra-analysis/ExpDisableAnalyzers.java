// Disable the analyzers named in the script arguments before auto-analysis.
// @category REAExperiment

import ghidra.app.script.GhidraScript;

public class ExpDisableAnalyzers extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String name : getScriptArgs()) {
            setAnalysisOption(currentProgram, name, "false");
            println("EXP disabled analyzer: " + name);
        }
    }
}
