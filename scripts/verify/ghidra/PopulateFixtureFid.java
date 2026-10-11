// Verifier-only: build a Function ID database from the program this script runs against.
// Arguments: output .fidbf path, library family, version, variant.
//@category FunctionID
import java.io.File;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;

public class PopulateFixtureFid extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if (arguments.length != 4) throw new IllegalArgumentException("expected path family version variant");
		File output = new File(arguments[0]);
		FidFileManager manager = FidFileManager.getInstance();
		manager.createNewFidDatabase(output);
		FidFile file = manager.addUserFidFile(output);
		if (file == null) throw new IllegalStateException("Function ID database was not created");
		FidDB database = file.getFidDB(true);
		try {
			FidPopulateResult result = new FidService().createNewLibraryFromPrograms(
				database, arguments[1], arguments[2], arguments[3],
				List.of(currentProgram.getDomainFile()), null,
				currentProgram.getLanguageID(), null, null, monitor);
			println("added=" + result.getTotalAdded() + " attempted=" + result.getTotalAttempted());
			database.saveDatabase("fixture", monitor);
		}
		finally {
			database.close();
		}
	}
}
