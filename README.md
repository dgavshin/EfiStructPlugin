# Monet
Implementation of a GraphService for Ghidra 9.1.2

To build this plugin, you will need to install Eclipse and set it up to build Ghidra projects as described in the Ghidra documentation (see `<Ghidra 9.1.2 install directory>/docs/GhidraClass/AdvancedDevelopment/GhidraAdvancedDevelopment.html#12.0`)

Note that you will have to set your classpath to be able to build the project. After loading the project into Eclipse, select `Ghidra Dev -> Link Ghidra...` from the menu and follow through the dialogs.

After building, copy the `dist/ghidra_9.1.2_PUBLIC_<build_data>_Monet.zip` file into the `Extensions/Ghidra` directory in your Ghidra installation directory. Open the Ghidra project window and select the `File --> Install Extensions...` menu option and then select `Monet`. You will have to close Ghidra and restart it for the changes to take effect. On restart, Ghidra may ask if you want to configure new extensions. If so, select `yes` and click `MonetPlugin`.

You should then be able to select a function in the CodeBrowser and run the `GraphAST.java` script in the PCode category. You will also notice a new pull-down option in the Decompiler window for "Graph AST Control Flow" that will be available.

Note that after running the `GraphAST.java` script, you may have to manually open the Monet window by selecting the `Window -> MonetPlugin` option from the CodeBrowser menu.

Monet uses the JUNG library for graphics with the default mouse handler:
* Left mouse drag to pan
* Left mouse drag + shift for rotation
* Left mouse drag + ctrl for shear effect
* Scroll wheel to zoom


