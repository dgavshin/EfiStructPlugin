package efistruct.Tree;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.options.editor.FontPropertyEditor;
import docking.util.GraphicsUtils;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.label.GLabel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionListener;
import efistruct.EfiEntry;
import efistruct.EfiGraphPlugin;
import efistruct.EfiGraphProvider;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.services.GoToService;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import resources.Icons;
import resources.ResourceManager;

import javax.swing.*;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.geom.Rectangle2D;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static efistruct.EfiGraphProvider.PMD;
import static efistruct.EfiGraphProvider.tool;
import static resources.Icons.EMPTY_ICON;

public class EfiTreeProvider {
	private final static String NAME = "EFI Tree";
	private static final Object TITLE = "EfiTree";
	private final Program program;
	private NumberIcon recurseIcon;

	private GTree tree;
	private final JComponent component;
	private JSplitPane splitPane;
	private final AtomicInteger recurseDepth = new AtomicInteger();

	private static final String RECURSE_DEPTH_PROPERTY_NAME = "efistruct.tree.recurse.depth";
	private static final String DEFAULT_RECURSE_DEPTH = "5";

	private static final ImageIcon REFRESH_ICON = Icons.REFRESH_ICON;
	private static final Icon REFRESH_NOT_NEEDED_ICON = ResourceManager.getDisabledIcon(REFRESH_ICON, 60);
	public static Set<String> programsInUsed = new HashSet<>();

	public static final Icon FOUNDED_ICON = ResourceManager.loadImage("images/founded.png");
	public static final Icon FUNCTION_ICON = ResourceManager.loadImage("images/function.png");
	public static final Icon PROTOCOL_ICON = ResourceManager.loadImage("images/protocol.png");
	public static final Icon ROOT_ICON = ResourceManager.loadImage("images/root.png");
	public static final Icon SOURCE_ICON = ResourceManager.loadImage("images/source.png");

	public static final Font LIBERATION_FONT = new Font("Liberation Mono Regular", Font.PLAIN, 16);

	public EfiTreeProvider(Program program)
	{
		this.program = program;
		component = buildComponent();

		programsInUsed.add(EfiGraphProvider.program.getName());
		// try to give the trees a suitable amount of space by default
		component.setPreferredSize(new Dimension(800, 400));
		loadRecurseDepthPreference();
		createActions();
		doUpdate();
	}

	private void loadRecurseDepthPreference() {
		String value = Preferences.getProperty(RECURSE_DEPTH_PROPERTY_NAME, DEFAULT_RECURSE_DEPTH);
		int intValue;
		try {
			intValue = Integer.parseInt(value);
		}
		catch (NumberFormatException nfe) {
			intValue = Integer.parseInt(DEFAULT_RECURSE_DEPTH);
		}

		recurseDepth.set(intValue);
	}

	private void createActions()
	{
		//
		// recurse depth		
		//
		DockingAction recurseDepthAction = new DockingAction("Recurse Depth", EfiGraphProvider.plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				NumberInputDialog dialog =
						new NumberInputDialog("", "", recurseDepth.get(), 0, Integer.MAX_VALUE, false);
				if (!dialog.show()) {
					return;
				}

				int newValue = dialog.getValue();
				setRecurseDepth(newValue);
			}
		};
		recurseDepthAction.setDescription(
				"<html>Recurse Depth<br><br>Limits the depth to " + "which recursing tree operations" +
						"<br> will go.  Example operations include <b>Expand All</b> and filtering");
		recurseIcon = new NumberIcon(recurseDepth.get());
		recurseDepthAction.setToolBarData(
				new ToolBarData(recurseIcon, Integer.toString(2), "2"));
		tool.addLocalAction(EfiGraphPlugin.provider, recurseDepthAction);

		
		//
		// Refresh
		//
		DockingAction refreshAction = new DockingAction("Refresh", EfiGraphProvider.plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doUpdate();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_ICON, Integer.toString(1)));
		refreshAction.setEnabled(true);
		refreshAction.setDescription("<html>Push at any time to refresh the current trees.<br>" +
				"This is highlighted when the data <i>may</i> be stale.<br>");
		tool.addLocalAction(EfiGraphPlugin.provider, refreshAction);
	}

	private JComponent buildComponent() {
		JPanel container = new JPanel(new BorderLayout());

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

		tree = createTree();
		GTreeSelectionListener treeSelectionListener = e -> {

			if (e.getEventOrigin() != GTreeSelectionEvent.EventOrigin.USER_GENERATED)
				return ;

			TreePath path = e.getPath();
			if (path == null)
				return ;

			EfiNode node = (EfiNode) path.getLastPathComponent();

			if (!node.entry.getType().equals("Protocol"))
				return ;

			Address sourceAddress = node.entry.getAddress();
			goTo(new ProgramLocation(program, sourceAddress));
		};
		tree.addGTreeSelectionListener(treeSelectionListener);

		GTreeSelectionListener contextSelectionListener = e -> notifyContextChanged();
		tree.addGTreeSelectionListener(contextSelectionListener);

		JPanel panel = createTreePanel(tree);
		panel.setFont(panel.getFont().deriveFont(22.0f));
		splitPane.setLeftComponent(panel);
		splitPane.setFont(panel.getFont().deriveFont(22.0f));
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
		container.setFont(container.getFont().deriveFont(22.0f));
		Msg.info(this, container.getFont().getName());

		return container;
	}

	private JPanel createTreePanel(GTree tree) {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(new GLabel("Efi Tree"), BorderLayout.NORTH);
		panel.add(tree, BorderLayout.CENTER);

		return panel;
	}

	private void goTo(ProgramLocation location) {
		boolean isFiringNavigationEvent = true;
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

//		for (Font font: GraphicsEnvironment.getLocalGraphicsEnvironment().getAllFonts()) {
//			Msg.info(this, font.getName());
//			Msg.info(this, font.getAttributes().toString());
//			if (font.getName().equals("Liberation Mono"))
//				tree.setFont(font);
//		}
		tree.setFont(tree.getFont().deriveFont(22.0f));

//		tree.setSize(200, 200);
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
		EfiNode rootNode = new EfiNode(new EfiEntry("Functions", "Root"), recurseDepth, false);
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

	//
	//	Recurse
	//
	public void setRecurseDepth(int depth) {
		if (depth < 1) {
			return; // always have at least one level showing
		}

		if (recurseDepth.get() == depth) {
			return;
		}

		this.recurseDepth.set(depth);
		this.recurseIcon.setNumber(depth);

		saveRecurseDepth();
	}

	private void saveRecurseDepth() {
		Preferences.setProperty(RECURSE_DEPTH_PROPERTY_NAME, Integer.toString(recurseDepth.get()));
		Preferences.store();
	}

	private static class NumberIcon implements Icon {
		private String number;
		private float bestFontSize = -1;

		NumberIcon(int number) {
			this.number = Integer.toString(number);
		}

		void setNumber(int number) {
			this.number = Integer.toString(number);
			bestFontSize = -1;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(Color.WHITE);
			g.fillRect(x, y, getIconWidth(), getIconHeight());
			g.setColor(new Color(0xb5d5ff));
			g.drawRect(x, y, getIconWidth(), getIconHeight());

			float fontSize = getMaxFontSize(g, getIconWidth() - 1, getIconHeight());
			Font originalFont = g.getFont();
			Font textFont = originalFont.deriveFont(fontSize).deriveFont(Font.BOLD);
			g.setFont(textFont);

			FontMetrics fontMetrics = g.getFontMetrics(textFont);
			Rectangle2D stringBounds = fontMetrics.getStringBounds(number, g);
			int textHeight = (int) stringBounds.getHeight();
			int iconHeight = getIconHeight();
			int space = y + iconHeight - textHeight;
			int halfSpace = space >> 1;
			int baselineY = y + iconHeight - halfSpace;// - halfTextHeight;// + halfTextHeight;

			int textWidth = (int) stringBounds.getWidth();
			int iconWidth = getIconWidth();
			int halfWidth = iconWidth >> 1;
			int halfTextWidth = textWidth >> 1;
			int baselineX = x + halfWidth - halfTextWidth;

			g.setColor(Color.BLACK);
			JComponent jc = null;
			if (c instanceof JComponent) {
				jc = (JComponent) c;
			}
			GraphicsUtils.drawString(jc, g, number, baselineX, baselineY);
		}

		private float getMaxFontSize(Graphics g, int width, int height) {
			if (bestFontSize > 0) {
				return bestFontSize;
			}

			float size = 12f;
			Font font = g.getFont().deriveFont(size); // reasonable default
			if (textFitsInFont(g, font, width, height)) {
				bestFontSize = size;
				return bestFontSize;
			}

			do {
				size--;
				font = g.getFont().deriveFont(size);
			}
			while (!textFitsInFont(g, font, width, height));

			bestFontSize = Math.max(1f, size);
			return bestFontSize;
		}

		private boolean textFitsInFont(Graphics g, Font font, int width, int height) {
			FontMetrics fontMetrics = g.getFontMetrics(font);
			int textWidth = fontMetrics.stringWidth(number);
			if (textWidth > width) {
				return false;
			}

			int textHeight = fontMetrics.getHeight();
			return textHeight < height;
		}

		@Override
		public int getIconHeight() {
			return 16;
		}

		@Override
		public int getIconWidth() {
			return 16;
		}
	}
}
