/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package efistruct;

import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import efistruct.Tree.EfiTreeProvider;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import static efistruct.EfiGraphProvider.cacheTool;
import static ghidra.graph.program.ProgramGraphPlugin.MENU_GRAPH;

@PluginInfo(
		status = PluginStatus.UNSTABLE,
		packageName = "EfiGraphPlugin",
		category = PluginCategoryNames.GRAPH,
		shortDescription = "Create graph based on EFI protocols",
		description = "This plugin conjunction only with efiSeek analyzer. EfiGraphPlugin retrieves" +
				" meta data from memory of current program and based on this creates links between protocols " +
				"functions and globals services",
		servicesRequired = {ProgramManager.class},
		eventsConsumed = {ProgramActivatedPluginEvent.class}
)

public class EfiGraphPlugin extends ProgramPlugin {

	public static HashMap<String, Symbol> USER_SYMBOLS = new HashMap<>();
	public static EfiGraphProvider provider;
	public static EfiTreeProvider treeProvider;

	static String PROJECT_PATH;

	public EfiGraphPlugin(PluginTool tool) {
		super(tool, true, true);
		PROJECT_PATH = tool.getProject().getProjectLocator().getProjectDir().getPath();
		this.tool = tool;
	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);

		provider = new EfiGraphProvider(tool, this, program);
//		treeProvider = new EfiTreeProvider(tool, this, program);;
	}

	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		if (cacheTool != null)
			cacheTool.cacheFile(cacheTool.PMD, program.getName());
	}

	private void initServices(Program program) {

	}

	/**
	 * Retrieving all user symbols
	 *
	 * @param program program for retrieving symbols from Symbol Table
	 * @return list of symbols in specified program with {@link SourceType#USER_DEFINED}
	 */
	public static ArrayList<Symbol> getUserSymbols(Program program) {
		ArrayList<Symbol> symbols = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true))
			if (symbol.getSource() == SourceType.USER_DEFINED)
				symbols.add(symbol);
		return (symbols);
	}
}
