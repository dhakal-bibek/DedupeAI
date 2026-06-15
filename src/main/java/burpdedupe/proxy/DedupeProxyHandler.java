package burpdedupe.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burpdedupe.core.DedupeEngine;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Stamps each new HTTP history entry with a UNIQUE / DUPE verdict in the Notes column.
 *
 * <p>We classify in {@code handleResponseReceived} — that's the moment the entry lands
 * in HTTP history, and the annotations we return are what shows up there. The other
 * callback ({@code handleResponseToBeSent}) is just pass-through.
 *
 * <p>The notes string is prefixed with a fixed tag so a column-sort groups verdicts
 * cleanly: "[DEDUPE] UNIQUE", "[DEDUPE] DUPE x3", etc. The user can mass-select all
 * UNIQUE rows after sorting by Notes.
 */
public final class DedupeProxyHandler implements ProxyResponseHandler {

    public static final String NOTE_PREFIX = "[DEDUPE]";

    private final MontoyaApi api;
    private final DedupeEngine engine;
    private final AtomicBoolean enabled;
    private final AtomicBoolean colorize;
    private final AtomicBoolean preserveExistingNotes;
    private final UniqueFeed feed;

    public DedupeProxyHandler(MontoyaApi api, DedupeEngine engine,
                              AtomicBoolean enabled, AtomicBoolean colorize,
                              AtomicBoolean preserveExistingNotes, UniqueFeed feed) {
        this.api = api;
        this.engine = engine;
        this.enabled = enabled;
        this.colorize = colorize;
        this.preserveExistingNotes = preserveExistingNotes;
        this.feed = feed;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        if (!enabled.get()) {
            return ProxyResponseReceivedAction.continueWith(response);
        }

        DedupeEngine.Result result;
        try {
            // Attacker/victim role ports (PORT_RULES) dedupe across identities: the same request from
            // either login shares one count, so the victim's repeat of an attacker-seen endpoint becomes
            // DUPE x2. Cookie / Authorization / the injected tag header and the response status are
            // ignored for the signature. Everything else dedupes normally.
            if (PortHighlightHandler.isRolePort(response.listenerInterface())) {
                result = engine.classifyCrossIdentity(
                        response.initiatingRequest(), PortHighlightHandler.injectedHeaderNames());
            } else {
                result = engine.classify(response.initiatingRequest(), response);
            }
        } catch (RuntimeException e) {
            // Never let a bug here block traffic.
            api.logging().logToError("[burp-dedupe] classify failed: " + e);
            return ProxyResponseReceivedAction.continueWith(response);
        }

        Annotations current = response.annotations();
        String existingNotes = current != null && current.hasNotes() ? current.notes() : "";
        String dedupeNote = NOTE_PREFIX + " " + result.shortLabel();
        String newNotes;
        if (preserveExistingNotes.get() && !existingNotes.isEmpty() && !existingNotes.contains(NOTE_PREFIX)) {
            newNotes = dedupeNote + " | " + existingNotes;
        } else {
            // Strip any prior dedupe note (re-classifications can occur after config reset).
            String stripped = stripDedupeNote(existingNotes);
            newNotes = stripped.isEmpty() ? dedupeNote : dedupeNote + " | " + stripped;
        }

        Annotations updated = (current == null ? Annotations.annotations() : current).withNotes(newNotes);
        if (colorize.get()) {
            // Colour is port- and verdict-aware (see PortHighlightHandler.colorFor): on the
            // attacker/victim ports unique vs dupe get distinct colours; other ports fall back
            // to the default yellow=unique / gray=dupe.
            updated = updated.withHighlightColor(
                    PortHighlightHandler.colorFor(response.listenerInterface(), result.verdict()));
        }

        // Push every UNIQUE straight to the live view, in memory — the live "Dedupe Live" tab no
        // longer depends on re-reading these notes back out of Proxy history (which breaks if another
        // extension overwrites the Notes, or annotations don't round-trip). The tab still polls
        // history as a back-fill and dedupes the two paths by the proxy message id.
        if (feed != null && result.verdict() == DedupeEngine.Verdict.UNIQUE) {
            try {
                feed.publish(HttpRequestResponse.httpRequestResponse(
                        response.initiatingRequest(), response, updated), response.messageId());
            } catch (RuntimeException e) {
                api.logging().logToError("[burp-dedupe] live publish failed: " + e);
            }
        }

        return ProxyResponseReceivedAction.continueWith(response, updated);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private static String stripDedupeNote(String notes) {
        if (notes == null || notes.isEmpty()) return "";
        // Notes we wrote look like: "[DEDUPE] UNIQUE" or "[DEDUPE] DUPE x3 | original notes"
        int idx = notes.indexOf(NOTE_PREFIX);
        if (idx != 0) return notes;
        int sep = notes.indexOf(" | ");
        return sep < 0 ? "" : notes.substring(sep + 3);
    }
}
