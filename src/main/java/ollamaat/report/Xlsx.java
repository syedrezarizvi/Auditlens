package ollamaat.report;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Minimal, dependency-free writer for a multi-sheet .xlsx (OOXML SpreadsheetML) workbook. Uses inline strings (no
 * shared-strings part), bordered wrapped body cells, and optional embedded pictures. A "table" sheet has a bold
 * header row, frozen header, autofilter and column widths; a "plain" sheet is free-form rows (used for cover pages).
 * Avoids bundling Apache POI.
 */
public final class Xlsx {

    /** A picture anchored at a cell. {@code ext} is png, jpeg or gif. Size is in pixels. */
    public record Image(byte[] data, String ext, int col, int row0, int widthPx, int heightPx) {}

    public static final class Sheet {
        final String name;
        boolean table;
        final List<String> headers = new ArrayList<>();
        final List<Integer> widths = new ArrayList<>();
        final List<List<String>> rows = new ArrayList<>();
        final List<Image> images = new ArrayList<>();
        Sheet(String name, boolean table) { this.name = clean(name); this.table = table; }
    }

    private final List<Sheet> sheets = new ArrayList<>();
    private Sheet cur;

    /** Creates the workbook with one table sheet (define its columns with {@link #header}). */
    public Xlsx(String sheetName) {
        cur = new Sheet(sheetName, true);
        sheets.add(cur);
    }

    /** Defines the header row and column widths of the current table sheet. Lengths must match. */
    public Xlsx header(List<String> cols, List<Integer> colWidths) {
        cur.headers.clear(); cur.headers.addAll(cols);
        cur.widths.clear(); cur.widths.addAll(colWidths);
        return this;
    }

    /** Column widths only, for a plain (free-form) sheet. */
    public Xlsx widths(List<Integer> colWidths) {
        cur.widths.clear(); cur.widths.addAll(colWidths);
        return this;
    }

    /** Turns the current sheet into a plain (free-form) sheet. */
    public Xlsx plain() { cur.table = false; return this; }

    public Xlsx row(List<String> cells) { cur.rows.add(new ArrayList<>(cells)); return this; }

    /** Starts a new sheet and makes it current. A plain sheet has no header row, filter or frozen pane. */
    public Xlsx addSheet(String name, boolean table) {
        cur = new Sheet(name, table);
        sheets.add(cur);
        return this;
    }

    /** Places a picture on the current sheet, anchored at a zero-based column and row. */
    public Xlsx image(byte[] data, String ext, int col, int row0, int widthPx, int heightPx) {
        String e = ext == null ? "" : ext.toLowerCase(java.util.Locale.ROOT);
        if (data == null || data.length == 0 || !(e.equals("png") || e.equals("jpeg") || e.equals("jpg") || e.equals("gif"))) return this;
        cur.images.add(new Image(data, e.equals("jpg") ? "jpeg" : e, col, row0, widthPx, heightPx));
        return this;
    }

    public byte[] toBytes() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ZipOutputStream z = new ZipOutputStream(bos)) {
            int media = 0, drawings = 0;
            List<String> imageParts = new ArrayList<>();
            List<String> imageExts = new ArrayList<>();
            List<String> drawingParts = new ArrayList<>();
            List<String> sheetRelsParts = new ArrayList<>();
            // Pre-compute parts for pictures so the content types and relationships can reference them.
            List<String[]> pending = new ArrayList<>();
            for (int i = 0; i < sheets.size(); i++) {
                Sheet s = sheets.get(i);
                if (s.images.isEmpty()) continue;
                drawings++;
                drawingParts.add("xl/drawings/drawing" + drawings + ".xml");
                sheetRelsParts.add("xl/worksheets/_rels/sheet" + (i + 1) + ".xml.rels");
            }

            put(z, "[Content_Types].xml", contentTypes(sheets.size(), drawingParts, sheets));
            put(z, "_rels/.rels", RELS);
            put(z, "xl/workbook.xml", workbook());
            put(z, "xl/_rels/workbook.xml.rels", wbRels(sheets.size()));
            put(z, "xl/styles.xml", STYLES);
            int d = 0;
            for (int i = 0; i < sheets.size(); i++) {
                Sheet s = sheets.get(i);
                put(z, "xl/worksheets/sheet" + (i + 1) + ".xml", sheet(s));
                if (s.images.isEmpty()) continue;
                d++;
                put(z, "xl/worksheets/_rels/sheet" + (i + 1) + ".xml.rels",
                        rel("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing", "../drawings/drawing" + d + ".xml"));
                StringBuilder dr = new StringBuilder(rels());
                int j = 0;
                StringBuilder anchors = new StringBuilder();
                for (Image img : s.images) {
                    media++; j++;
                    String mediaName = "image" + media + "." + img.ext();
                    put(z, "xl/media/" + mediaName, null, img.data());
                    imageExts.add(img.ext());
                    dr.insert(dr.length() - "</Relationships>".length(),
                            "<Relationship Id=\"rId" + j + "\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"../media/" + mediaName + "\"/>");
                    anchors.append(anchor(img, j));
                }
                put(z, "xl/drawings/drawing" + d + ".xml",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                        + "<xdr:wsDr xmlns:xdr=\"http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing\""
                        + " xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">" + anchors + "</xdr:wsDr>");
                put(z, "xl/drawings/_rels/drawing" + d + ".xml.rels", dr.toString());
            }
            z.finish();
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("xlsx build failed: " + e.getMessage(), e);
        }
    }

    // ---- parts ----------------------------------------------------------------
    private String workbook() {
        StringBuilder b = new StringBuilder();
        b.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")
         .append("<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"")
         .append(" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>");
        for (int i = 0; i < sheets.size(); i++)
            b.append("<sheet name=\"").append(esc(sheets.get(i).name)).append("\" sheetId=\"").append(i + 1)
             .append("\" r:id=\"rId").append(i + 1).append("\"/>");
        b.append("</sheets></workbook>");
        return b.toString();
    }

    private static String wbRels(int n) {
        StringBuilder b = new StringBuilder(rels());
        for (int i = 0; i < n; i++)
            b.insert(b.length() - "</Relationships>".length(),
                    "<Relationship Id=\"rId" + (i + 1) + "\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet" + (i + 1) + ".xml\"/>");
        b.insert(b.length() - "</Relationships>".length(),
                "<Relationship Id=\"rId" + (n + 1) + "\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>");
        return b.toString();
    }

    private static String contentTypes(int n, List<String> drawingParts, List<Sheet> sheets) {
        StringBuilder b = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
            + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
            + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
            + "<Default Extension=\"png\" ContentType=\"image/png\"/>"
            + "<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/>"
            + "<Default Extension=\"gif\" ContentType=\"image/gif\"/>"
            + "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
            + "<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
        for (int i = 0; i < n; i++)
            b.append("<Override PartName=\"/xl/worksheets/sheet").append(i + 1)
             .append(".xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
        for (String d : drawingParts)
            b.append("<Override PartName=\"/").append(d).append("\" ContentType=\"application/vnd.openxmlformats-officedocument.drawing+xml\"/>");
        return b.append("</Types>").toString();
    }

    private String sheet(Sheet s) {
        StringBuilder b = new StringBuilder();
        b.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        b.append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\""
                + " xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">");
        // CT_Worksheet requires a fixed child order: dimension, sheetViews, cols, sheetData, autoFilter, ..., drawing.
        int cols = Math.max(1, s.table ? s.headers.size() : s.widths.size());
        int firstRow = s.table ? 1 : 1;
        int lastRow = Math.max(1, s.rows.size() + (s.table ? 1 : 0));
        String ref = "A1:" + colLetters(cols - 1) + lastRow;
        b.append("<dimension ref=\"").append(ref).append("\"/>");
        if (s.table) b.append("<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>");
        else b.append("<sheetViews><sheetView workbookViewId=\"0\" showGridLines=\"0\"/></sheetViews>");
        if (!s.widths.isEmpty()) {
            b.append("<cols>");
            for (int i = 0; i < s.widths.size(); i++)
                b.append("<col min=\"").append(i + 1).append("\" max=\"").append(i + 1)
                 .append("\" width=\"").append(s.widths.get(i)).append("\" customWidth=\"1\"/>");
            b.append("</cols>");
        }
        b.append("<sheetData>");
        int r = firstRow;
        if (s.table) {
            b.append("<row r=\"1\">");
            for (int c = 0; c < s.headers.size(); c++) b.append(cell(ref(c, 1), s.headers.get(c), 1));
            b.append("</row>");
            r = 2;
        }
        for (List<String> row : s.rows) {
            b.append("<row r=\"").append(r).append("\">");
            int width = s.table ? s.headers.size() : Math.max(row.size(), 1);
            for (int c = 0; c < width; c++) {
                String v = c < row.size() ? row.get(c) : "";
                b.append(cell(ref(c, r), v, 2));
            }
            b.append("</row>");
            r++;
        }
        b.append("</sheetData>");
        if (s.table) b.append("<autoFilter ref=\"").append("A1:").append(colLetters(Math.max(1, s.headers.size()) - 1)).append(Math.max(1, s.rows.size() + 1)).append("\"/>");
        if (!s.images.isEmpty()) b.append("<drawing r:id=\"rId1\"/>");
        b.append("</worksheet>");
        return b.toString();
    }

    private static String anchor(Image img, int relId) {
        long cx = img.widthPx() * 9525L, cy = img.heightPx() * 9525L;
        return "<xdr:oneCellAnchor>"
            + "<xdr:from><xdr:col>" + img.col() + "</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>" + img.row0() + "</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>"
            + "<xdr:ext cx=\"" + cx + "\" cy=\"" + cy + "\"/>"
            + "<xdr:pic><xdr:nvPicPr><xdr:cNvPr id=\"" + (relId + 1) + "\" name=\"Picture " + relId + "\"/>"
            + "<xdr:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></xdr:cNvPicPr></xdr:nvPicPr>"
            + "<xdr:blipFill><a:blip xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" r:embed=\"rId" + relId + "\"/>"
            + "<a:stretch><a:fillRect/></a:stretch></xdr:blipFill>"
            + "<xdr:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"" + cx + "\" cy=\"" + cy + "\"/></a:xfrm>"
            + "<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:oneCellAnchor>";
    }

    private static String cell(String ref, String value, int style) {
        if (value == null) value = "";
        return "<c r=\"" + ref + "\" s=\"" + style + "\" t=\"inlineStr\"><is><t xml:space=\"preserve\">" + esc(value) + "</t></is></c>";
    }

    private static String ref(int col0, int row1) { return colLetters(col0) + row1; }

    private static String colLetters(int col0) {
        StringBuilder s = new StringBuilder();
        int n = col0;
        while (n >= 0) { s.insert(0, (char) ('A' + n % 26)); n = n / 26 - 1; }
        return s.toString();
    }

    private static void put(ZipOutputStream z, String name, String content) throws Exception {
        put(z, name, content, null);
    }

    private static void put(ZipOutputStream z, String name, String content, byte[] raw) throws Exception {
        z.putNextEntry(new ZipEntry(name));
        z.write(raw != null ? raw : content.getBytes(StandardCharsets.UTF_8));
        z.closeEntry();
    }

    private static String clean(String s) {
        String t = (s == null || s.isBlank() ? "Sheet" : s).replaceAll("[\\[\\]:*?/\\\\]", " ").trim();
        return t.length() <= 31 ? t : t.substring(0, 31);
    }

    static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '&' -> b.append("&amp;");
                case '<' -> b.append("&lt;");
                case '>' -> b.append("&gt;");
                case '"' -> b.append("&quot;");
                case '\'' -> b.append("&apos;");
                case '\r' -> {}
                default -> { if (ch == '\n' || ch == '\t' || ch >= 0x20) b.append(ch); }
            }
        }
        return b.toString();
    }

    private static String rels() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>";
    }

    private static String rel(String id, String type, String target) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            + "<Relationship Id=\"" + id + "\" Type=\"" + type + "\" Target=\"" + target + "\"/></Relationships>";
    }

    private static final String RELS =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>"
        + "</Relationships>";

    // style 0 = default; style 1 = header (bold, white on dark blue, wrap, centered); style 2 = body (wrap, top align, borders)
    private static final String STYLES =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        + "<fonts count=\"2\">"
        + "<font><sz val=\"11\"/><name val=\"Calibri\"/></font>"
        + "<font><b/><sz val=\"11\"/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/></font>"
        + "</fonts>"
        + "<fills count=\"3\">"
        + "<fill><patternFill patternType=\"none\"/></fill>"
        + "<fill><patternFill patternType=\"gray125\"/></fill>"
        + "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1F4E78\"/><bgColor indexed=\"64\"/></patternFill></fill>"
        + "</fills>"
        + "<borders count=\"2\">"
        + "<border><left/><right/><top/><bottom/><diagonal/></border>"
        + "<border><left style=\"thin\"><color rgb=\"FFBFBFBF\"/></left><right style=\"thin\"><color rgb=\"FFBFBFBF\"/></right>"
        + "<top style=\"thin\"><color rgb=\"FFBFBFBF\"/></top><bottom style=\"thin\"><color rgb=\"FFBFBFBF\"/></bottom><diagonal/></border>"
        + "</borders>"
        + "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>"
        + "<cellXfs count=\"3\">"
        + "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>"
        + "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"1\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\" vertical=\"center\" wrapText=\"1\"/></xf>"
        + "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" applyBorder=\"1\" applyAlignment=\"1\"><alignment vertical=\"top\" wrapText=\"1\"/></xf>"
        + "</cellXfs>"
        + "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>"
        + "</styleSheet>";
}
