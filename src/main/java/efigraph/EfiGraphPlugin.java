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
package efigraph;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

@PluginInfo(
        status = PluginStatus.UNSTABLE,
        packageName = "EfiGraphPlugin",
        category = PluginCategoryNames.GRAPH,
        shortDescription = "Create graph based on EFI protocols",
        description = "This plugin conjunction only with efiSeek analyzer. EfiGraphPlugin retrieves" +
                " meta data from memory of current program and based on this creates links between protocols " +
                "functions and globals services",
        servicesRequired = { ProgramManager.class },
        eventsConsumed = { ProgramActivatedPluginEvent.class }
)

public class EfiGraphPlugin extends ProgramPlugin {

    EfiGraphProvider        provider;
    static String           PROJECT_PATH;

    public EfiGraphPlugin(PluginTool tool) {
        super(tool, true, true);
        PROJECT_PATH = tool.getProject().getProjectLocator().getProjectDir().getPath();

        this.tool = tool;
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);

        provider = new EfiGraphProvider(tool, this, program);
        tool.getProject().getProjectData();
    }

    @Override
    protected void programDeactivated(Program program)
    {
        super.programDeactivated(program);
        if (EfiGraphProvider.cacheTool != null)
            EfiGraphProvider.cacheTool.cacheFile(EfiGraphProvider.cacheTool.PMD, program.getName());
    }
}
