package burpdedupe;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
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

            // Live unique history as its own always-on Burp tab (no pop-up needed; Ctrl+9 still works).
            api.userInterface().registerSuiteTab("Dedupe Live", DedupeTab.liveUniqueComponent(api));

            DedupeContextMenu contextMenu = new DedupeContextMenu(api, engine, stamper, tab::currentOverrides);
            api.userInterface().registerContextMenuItemsProvider(contextMenu);

            // Ctrl+9 (in Proxy HTTP history or the Site map) opens the LIVE unique-requests window,
            // which auto-collects every [DEDUPE] UNIQUE row and keeps updating — no selection needed.
            HotKeyHandler launchLiveUnique = event -> contextMenu.openLiveUnique();
            Registration hkHistory = api.userInterface()
                    .registerHotKeyHandler(HotKeyContext.PROXY_HTTP_HISTORY, "Ctrl+9", launchLiveUnique);
            Registration hkSiteMap = api.userInterface()
                    .registerHotKeyHandler(HotKeyContext.SITE_MAP_CONTENTS_TABLE, "Ctrl+9", launchLiveUnique);

            // Burp doesn't release hotkeys automatically on unload, so a reload otherwise warns
            // "Unable to register hotkey 'Ctrl+9' as already assigned". Deregister them ourselves.
            api.extension().registerUnloadingHandler(() -> {
                safeDeregister(hkHistory);
                safeDeregister(hkSiteMap);
            });

            if (tab.isAutoStampEnabled()) {
                tab.startHistoryStamp();
            }
        });

        api.extension().registerUnloadingHandler(() ->
                api.logging().logToOutput("[burp-dedupe] unloaded"));

        api.logging().logToOutput("[burp-dedupe] loaded. Default preset: " + engine.config().preset);
    }

    /** Best-effort deregistration — ignores a null/already-gone registration so unload never throws. */
    private static void safeDeregister(Registration r) {
        try {
            if (r != null && r.isRegistered()) r.deregister();
        } catch (RuntimeException ignored) {
            // best-effort cleanup during unload
        }
    }
}
