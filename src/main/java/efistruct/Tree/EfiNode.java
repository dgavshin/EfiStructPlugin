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
package efistruct.Tree;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import efistruct.EfiEntry;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class EfiNode extends GTreeSlowLoadingNode {

	protected final EfiEntry entry;
	protected final Address functionAddress;
	protected String name;

	EfiNode(EfiEntry entry) {

//		MultiIcon incomingFunctionIcon = new MultiIcon(INCOMING_ICON, false, 32, 16);
//		TranslateIcon translateIcon = new TranslateIcon(Efi.FUNCTION_ICON, 16, 0);
//		incomingFunctionIcon.addIcon(translateIcon);
//		INCOMING_FUNCTION_ICON = incomingFunctionIcon;

//		setAllowsDuplicates(!filterDuplicates);
		this.entry = entry;
		this.functionAddress = entry.getAddress();
	}

	public Function getContainingFunction() {
		return entry.getFunction();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException
	{

		ArrayList<EfiEntry> entries = this.entry.getReferences();
		List<GTreeNode> nodes = new ArrayList<>();
		for (EfiEntry reference : entries) {
			monitor.checkCanceled();
			nodes.add(new EfiNode(reference));
		}
		addNodes(nodes);
		return nodes;
	}

	@Override
	public Icon getIcon(boolean expanded) {
//		if (icon == null) {
//			icon = INCOMING_FUNCTION_ICON;
//			if (functionIsInPath()) {
//				icon = CallTreePlugin.RECURSIVE_ICON;
//			}
//		}
//		return icon;
		return null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}
}
