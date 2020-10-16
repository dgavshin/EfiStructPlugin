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
import efistruct.EfiProgramResearcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import javax.swing.tree.TreePath;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static efistruct.Tree.EfiTreeProvider.*;
import static efistruct.Tree.EfiTreeProvider.programsInUsed;

public class EfiNode extends GTreeSlowLoadingNode {

	protected final EfiEntry entry;
	protected final Address functionAddress;
	private final boolean matched;
	protected AtomicInteger filterDepth;
	protected String name;
	private int depth = -1;
	private Icon icon;

	public EfiNode(EfiEntry entry, AtomicInteger filterDepth, boolean matched) {

//		MultiIcon incomingFunctionIcon = new MultiIcon(INCOMING_ICON, false, 32, 16);
//		TranslateIcon translateIcon = new TranslateIcon(Efi.FUNCTION_ICON, 16, 0);
//		incomingFunctionIcon.addIcon(translateIcon);
//		INCOMING_FUNCTION_ICON = incomingFunctionIcon;

//		setAllowsDuplicates(!filterDuplicates);
		this.filterDepth = filterDepth;
		this.entry = entry;
		this.name = entry.getName();
		this.functionAddress = entry.getAddress();
		this.matched = matched;

		switch (entry.getType())
		{
			case "Protocol":
				this.icon = PROTOCOL_ICON;
				break;
			case "Function":
				this.icon = FUNCTION_ICON;
				break;
			case "Root":
				this.icon = ROOT_ICON;
				break;
			case "Source":
				this.icon = SOURCE_ICON;
				break;
		}
		if (matched)
			this.icon = FOUNDED_ICON;

	}

	public Function getContainingFunction() {
		return entry.getFunction();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

		if (this.entry.getType().equals("Protocol"))
			findReferences();
		Set<GTreeNode> nodes = new HashSet<>();
		for (EfiEntry reference : this.entry.getReferences())
		{
			monitor.checkCanceled();
			nodes.add(new EfiNode(reference, this.filterDepth, false));
		}
		addNodes(new ArrayList<>(nodes));
		return new ArrayList<>(nodes);
	}

	public void findReferences() {
		EfiProgramResearcher epr = new EfiProgramResearcher(this.entry);
		epr.founded_programs.forEach(e -> {
			if (!programsInUsed.contains(e.getName()))
				entry.addReference(e.toEfiEntry());
		});
	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		if (depth() > filterDepth.get()) {
			return 1;
		}
		return super.loadAll(monitor);
	}

	private int depth() {
		if (depth < 0) {
			TreePath treePath = getTreePath();
			Object[] path = treePath.getPath();
			depth = path.length;
		}
		return depth;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return icon;
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
