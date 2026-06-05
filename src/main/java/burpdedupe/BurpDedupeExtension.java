package burpdedupe;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burpdedupe.core.DedupeEngine;
import burpdedupe.core.SignatureConfig;
import burpdedupe.proxy.DedupeProxyHandler;
import burpdedupe.proxy.HistoryStamper;
import burpdedupe.proxy.PortHighlightHandler;
import burpdedupe.ui.DedupeContextMenu;
import burpdedupe.ui.DedupeTab;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;

public class BurpDedupeExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Dedupe");

        DedupeEngine engine = new DedupeEngine(api, SignatureConfig.forPreset(SignatureConfig.Preset.DEFAULT));
        AtomicBoolean enabled = new AtomicBoolean(true);
        AtomicBoolean colorize = new AtomicBoolean(true);
        AtomicBoolean preserveNotes = new AtomicBoolean(true);

        DedupeProxyHandler proxyHandler = new DedupeProxyHandler(api, engine, enabled, colorize, preserveNotes);
        api.proxy().registerResponseHandler(proxyHandler);

        // Port-based highlighting + header injection (attacker/victim tagging by listener port).
        api.proxy().registerRequestHandler(new PortHighlightHandler(api));
        PortHighlightHandler.PORT_RULES.forEach((port, rule) ->
                api.logging().logToOutput("[burp-dedupe] port " + port + " -> unique="
                        + rule.uniqueColor().displayName() + " dupe=" + rule.dupeColor().displayName()
                        + " " + rule.headers()));

        HistoryStamper stamper = new HistoryStamper(api, engine, colorize, preserveNotes);

        SwingUtilities.invokeLater(() -> {
            DedupeTab tab = new DedupeTab(api, engine, enabled, colorize, preserveNotes, stamper);
            api.userInterface().registerSuiteTab("Dedupe", tab.component());
            api.userInterface().registerContextMenuItemsProvider(
                    new DedupeContextMenu(api, engine, stamper, tab::currentOverrides));
            if (tab.isAutoStampEnabled()) {
                tab.startHistoryStamp();
            }
        });

        api.extension().registerUnloadingHandler(() ->
                api.logging().logToOutput("[burp-dedupe] unloaded"));

        api.logging().logToOutput("[burp-dedupe] loaded. Default preset: " + engine.config().preset);
    }
}
