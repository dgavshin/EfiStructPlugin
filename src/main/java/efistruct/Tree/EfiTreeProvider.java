package efistruct.Tree;

import docking.widgets.label.GLabel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionListener;
import efistruct.EfiEntry;
import efistruct.EfiGraphPlugin;
import efistruct.EfiGraphProvider;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.calltree.CallNode;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import javax.swing.*;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

import static efistruct.EfiGraphProvider.PMD;
import static resources.Icons.EMPTY_ICON;

public class EfiTreeProvider {
	private final static String NAME = "EFI Tree";
	private static final Object TITLE = "EfiTree";
	private final Program program;

	private GTree tree;
	private final JComponent component;
	private JSplitPane splitPane;
	private boolean isFiringNavigationEvent;

	public EfiTreeProvider(Program program)
	{
		this.program = program;
		component = buildComponent();

		// try to give the trees a suitable amount of space by default
		component.setPreferredSize(new Dimension(800, 400));
		doUpdate();
//		loadRecurseDepthPreference();
		createActions();
	}

	private void createActions()
	{

	}

	private JComponent buildComponent() {
		JPanel container = new JPanel(new BorderLayout());

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

		tree = createTree();
		GTreeSelectionListener treeSelectionListener = e -> {

			TreePath path = e.getPath();
			if (path == null) {
				return;
			}

			CallNode node = (CallNode) path.getLastPathComponent();
			Address sourceAddress = node.getSourceAddress();
			goTo(new ProgramLocation(program, sourceAddress));
		};
		tree.addGTreeSelectionListener(treeSelectionListener);

		GTreeSelectionListener contextSelectionListener = e -> notifyContextChanged();
		tree.addGTreeSelectionListener(contextSelectionListener);

		splitPane.setLeftComponent(createTreePanel(tree));
		splitPane.addHierarchyListener(new HierarchyListener() {
			@Override
			public void hierarchyChanged(HierarchyEvent e) {
				long changeFlags = e.getChangeFlags();
				if (HierarchyEvent.DISPLAYABILITY_CHANGED == (changeFlags &
						HierarchyEvent.DISPLAYABILITY_CHANGED)) {

					// check for the first time we are put together
					if (splitPane.isDisplayable()) {
						SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(.5));
						splitPane.removeHierarchyListener(this);
					}
				}
			}
		});

		container.add(splitPane, BorderLayout.CENTER);

		return container;
	}

	private JPanel createTreePanel(GTree tree) {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(new GLabel("Efi Tree"), BorderLayout.NORTH);
		panel.add(tree, BorderLayout.CENTER);

		return panel;
	}

	private void goTo(ProgramLocation location) {
		isFiringNavigationEvent = true;
		GoToService goToService = EfiGraphProvider.tool.getService(GoToService.class);
		if (goToService != null) {
			goToService.goTo(location);
			isFiringNavigationEvent = false;
			return;
		}

		// no goto service...navigate the old fashioned way (this doesn't have history)
		EfiGraphProvider.plugin.firePluginEvent(new ProgramLocationPluginEvent(EfiGraphPlugin.provider.getName(), location, program));
		isFiringNavigationEvent = false;
	}

	private GTree createTree() {
		GTree tree = new GTree(new EmptyRootNode());
		tree.setPaintHandlesForLeafNodes(false);
//		tree.setFilterVisible(false);
		return tree;
	}

	private void notifyContextChanged() {
		EfiGraphProvider.tool.contextChanged(EfiGraphPlugin.provider);
	}

	public JComponent getComponent() {
		return this.component;
	}

	private void doUpdate() {
		EfiNode rootNode = new EfiNode(new EfiEntry("Functions", "Root"));
		rootNode.entry.addReferences(PMD.getFunctions());
		tree.setRootNode(rootNode);
		//		setStale(false);
	}

	private static class PendingRootNode extends GTreeNode {

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Pending...";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}

	private static class EmptyRootNode extends GTreeNode {

		@Override
		public Icon getIcon(boolean expanded) {
			return EMPTY_ICON;
		}

		@Override
		public String getName() {
			return "No Function";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}
}
