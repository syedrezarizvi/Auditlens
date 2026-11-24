package ollamaat.ui;

/** Small Swing/threading helpers shared by the UI panels. */
final class Ui {
    private Ui() {}

    /** Run short background work (imports, sync, connection tests) off the Swing EDT on a daemon thread, so it never
     *  blocks the UI and never keeps Burp alive or piles up across extension reloads. UI updates must still be
     *  marshalled back with {@code SwingUtilities.invokeLater}. */
    static void bg(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
    }
}
