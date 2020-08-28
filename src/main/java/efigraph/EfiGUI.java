/*
 * Created by JFormDesigner on Sun Aug 23 14:31:47 MSK 2020
 */

package efigraph;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;

/**
 * @author shokk
 */
public class EfiGUI extends JFrame {
	public EfiGUI() {
		initComponents();
	}

	private void initComponents() {
		// JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
		// Generated using JFormDesigner Evaluation license - unknown
		dialogPane = new JPanel();
		contentPanel = new JPanel();
		tabbedPane1 = new JTabbedPane();
		contentPain = new JPanel();
		titleLabel = new JLabel();
		installPanel = new JPanel();
		installCheckBox = new JCheckBox();
		installPane = new JTextPane();
		locatePanel = new JPanel();
		locateCheckBox = new JCheckBox();
		locatePane = new JTextPane();
		buttonBar = new JPanel();
		buildButton = new JButton();

		//======== this ========
		var contentPane = getContentPane();
		contentPane.setLayout(new BorderLayout());

		//======== dialogPane ========
		{
			dialogPane.setBorder(new EmptyBorder(12, 12, 12, 12));
			dialogPane.setBorder ( new javax . swing. border .CompoundBorder ( new javax . swing. border .TitledBorder ( new javax
			. swing. border .EmptyBorder ( 0, 0 ,0 , 0) ,  "JF\u006frm\u0044es\u0069gn\u0065r \u0045va\u006cua\u0074io\u006e" , javax. swing
			.border . TitledBorder. CENTER ,javax . swing. border .TitledBorder . BOTTOM, new java. awt .
			Font ( "D\u0069al\u006fg", java .awt . Font. BOLD ,12 ) ,java . awt. Color .red
			) ,dialogPane. getBorder () ) ); dialogPane. addPropertyChangeListener( new java. beans .PropertyChangeListener ( ){ @Override
			public void propertyChange (java . beans. PropertyChangeEvent e) { if( "\u0062or\u0064er" .equals ( e. getPropertyName (
			) ) )throw new RuntimeException( ) ;} } );
			dialogPane.setLayout(new BorderLayout());

			//======== contentPanel ========
			{
				contentPanel.setLayout(new GridLayout());

				//======== tabbedPane1 ========
				{

					//======== contentPain ========
					{
						contentPain.setLayout(new GridLayout(3, 0));

						//---- titleLabel ----
						titleLabel.setText("Choose setting for searching locate/install functions in another files");
						titleLabel.setFont(titleLabel.getFont().deriveFont(titleLabel.getFont().getSize() + 2f));
						contentPain.add(titleLabel);

						//======== installPanel ========
						{
							installPanel.setLayout(new GridLayout(2, 0));

							//---- installCheckBox ----
							installCheckBox.setText("Instal Protocol");
							installCheckBox.setSelected(true);
							installPanel.add(installCheckBox);

							//---- installPane ----
							installPane.setText("If true, clicking on the vertex with the CTRL held down will show which EFI files this Protocol was LOCATED");
							installPanel.add(installPane);
						}
						contentPain.add(installPanel);

						//======== locatePanel ========
						{
							locatePanel.setLayout(new GridLayout(2, 0));

							//---- locateCheckBox ----
							locateCheckBox.setText("Locate Protocol");
							locateCheckBox.setSelected(true);
							locatePanel.add(locateCheckBox);

							//---- locatePane ----
							locatePane.setText("If true, clicking on the vertex with the CTRL held down will show which EFI files this Protocol was INSTALLED");
							locatePanel.add(locatePane);
						}
						contentPain.add(locatePanel);
					}
					tabbedPane1.addTab("Main settings", contentPain);
				}
				contentPanel.add(tabbedPane1);
			}
			dialogPane.add(contentPanel, BorderLayout.CENTER);

			//======== buttonBar ========
			{
				buttonBar.setBorder(new EmptyBorder(12, 0, 0, 0));
				buttonBar.setLayout(new GridBagLayout());
				((GridBagLayout)buttonBar.getLayout()).columnWidths = new int[] {0, 85, 80};
				((GridBagLayout)buttonBar.getLayout()).columnWeights = new double[] {1.0, 0.0, 0.0};

				//---- buildButton ----
				buildButton.setText("Build graph");
				buildButton.setFont(buildButton.getFont().deriveFont(buildButton.getFont().getSize() + 4f));
				buttonBar.add(buildButton, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0,
					GridBagConstraints.CENTER, GridBagConstraints.BOTH,
					new Insets(0, 0, 0, 0), 0, 0));
			}
			dialogPane.add(buttonBar, BorderLayout.SOUTH);
		}
		contentPane.add(dialogPane, BorderLayout.CENTER);
		pack();
		setLocationRelativeTo(getOwner());
		// JFormDesigner - End of component initialization  //GEN-END:initComponents
	}

	// JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
	// Generated using JFormDesigner Evaluation license - unknown
	private JPanel dialogPane;
	private JPanel contentPanel;
	private JTabbedPane tabbedPane1;
	private JPanel contentPain;
	private JLabel titleLabel;
	private JPanel installPanel;
	private JCheckBox installCheckBox;
	private JTextPane installPane;
	private JPanel locatePanel;
	private JCheckBox locateCheckBox;
	private JTextPane locatePane;
	private JPanel buttonBar;
	private JButton buildButton;
	// JFormDesigner - End of variables declaration  //GEN-END:variables


	public JPanel getDialogPane() {
		return dialogPane;
	}

	public JPanel getContentPanel() {
		return contentPanel;
	}

	public JTabbedPane getTabbedPane1() {
		return tabbedPane1;
	}

	public JPanel getContentPain() {
		return contentPain;
	}

	public JLabel getTitleLabel() {
		return titleLabel;
	}

	public JPanel getInstallPanel() {
		return installPanel;
	}

	public JCheckBox getInstallCheckBox() {
		return installCheckBox;
	}

	public JTextPane getInstallPane() {
		return installPane;
	}

	public JPanel getLocatePanel() {
		return locatePanel;
	}

	public JCheckBox getLocateCheckBox() {
		return locateCheckBox;
	}

	public JTextPane getLocatePane() {
		return locatePane;
	}

	public JPanel getButtonBar() {
		return buttonBar;
	}

	public JButton getBuildButton() {
		return buildButton;
	}
}
