// Verifier-only: build a file-backed H2 BSim database from the program this script runs against.
// Arguments: output database path (the .mv.db extension is added), database name.
//@category BSim
import java.io.File;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class PopulateFixtureBsim extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] arguments = getScriptArgs();
		if (arguments.length != 2) throw new IllegalArgumentException("expected path name");
		BSimServerInfo info = new BSimServerInfo(new File(arguments[0]).getAbsolutePath());
		try (FunctionDatabase database = BSimClientFactory.buildClient(info, false)) {
			CreateDatabase create = new CreateDatabase();
			create.info = new DatabaseInformation();
			create.info.databasename = arguments[1];
			create.config_template = "medium_nosize";
			create.info.trackcallgraph = true;
			ResponseInfo created = create.execute(database);
			if (created == null) throw new IllegalStateException(database.getLastError().message);
			DatabaseInformation dbInfo = database.getInfo();
			GenSignatures signatures = new GenSignatures(dbInfo.trackcallgraph);
			try {
				signatures.setVectorFactory(database.getLSHVectorFactory());
				signatures.addExecutableCategories(dbInfo.execats);
				signatures.addFunctionTags(dbInfo.functionTags);
				signatures.addDateColumnName(dbInfo.dateColumnName);
				// A headless import is saved only after its scripts finish, so the program has no
				// project URL yet; the fixture records no repository or path.
				signatures.openProgram(currentProgram, null, null, null, null, null);
				FunctionManager functions = currentProgram.getFunctionManager();
				Iterator<Function> iterator = functions.getFunctions(true);
				signatures.scanFunctions(iterator, functions.getFunctionCount(), monitor);
				DescriptionManager manager = signatures.getDescriptionManager();
				println("signed=" + manager.numFunctions());
				manager.listAllFunctions().forEachRemaining(description -> description.sortCallgraph());
				InsertRequest insert = new InsertRequest();
				insert.manage = manager;
				if (insert.execute(database) == null)
					throw new IllegalStateException(database.getLastError().message);
			}
			finally {
				signatures.dispose();
			}
		}
		finally {
			BSimH2FileDBConnectionManager.BSimH2FileDataSource source =
				BSimH2FileDBConnectionManager.getDataSourceIfExists(info);
			if (source != null) source.dispose();
		}
	}
}
