package com.pqcgateway.dashboard;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.pqcgateway.analytics.MetricsAggregator;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.collections.*;
import javafx.geometry.*;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.util.Duration;

import java.net.URI;
import java.net.http.*;
import java.util.*;
import java.util.stream.Collectors;

public class DashboardController {

    private static final String BASE_URL     = "http://127.0.0.1:8080/api";
    private static final int    POLL_SECS    = 2;
    private static final int    CHART_POINTS = 20;

    /* ── HTTP ──────────────────────────────────────────────────────────── */
    private final HttpClient http = HttpClient.newHttpClient();
    private final Gson       gson = new Gson();

    /* ── chart series ──────────────────────────────────────────────────── */
    private final XYChart.Series<Number, Number> latencySeries    = new XYChart.Series<>();
    private final XYChart.Series<Number, Number> throughputSeries = new XYChart.Series<>();
    private final XYChart.Series<Number, Number> lossSeries       = new XYChart.Series<>();
    private int chartX = 0;

    /* ── status labels ─────────────────────────────────────────────────── */
    private final Label lblConnection  = new Label("● Connecting…");
    private final Label lblAiDecision  = new Label("—");
    private final Label lblKyberLevel  = new Label("—");
    private final Label lblActivePath  = new Label("—");
    private final Label lblSessions    = new Label("0");
    private final Label lblAvgLatency  = new Label("—");
    private final Label lblAvgThrput   = new Label("—");
    private final Label lblDomMode     = new Label("—");

    /* ── events table ──────────────────────────────────────────────────── */
    private final ObservableList<PathEventRow> eventRows =
            FXCollections.observableArrayList();

    /* ── polling timer ─────────────────────────────────────────────────── */
    private Timeline poller;

    /* ══════════════════════════════════════════════════════════════════════
     * Layout
     * ══════════════════════════════════════════════════════════════════════ */

    public BorderPane buildLayout() {
        BorderPane root = new BorderPane();
        root.setTop(buildHeader());
        root.setCenter(buildCenter());
        root.setBottom(buildEventsTable());
        return root;
    }

    private HBox buildHeader() {
        Label title = new Label("PQC Gateway — Live Dashboard");
        title.setFont(Font.font("Monospaced", 18));
        title.getStyleClass().add("header-title");

        lblConnection.getStyleClass().add("status-connected");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        HBox header = new HBox(16, title, spacer, lblConnection);
        header.setPadding(new Insets(12, 16, 12, 16));
        header.setAlignment(Pos.CENTER_LEFT);
        header.getStyleClass().add("header-bar");
        return header;
    }

    private SplitPane buildCenter() {
        SplitPane split = new SplitPane(buildCharts(), buildStatusPanel());
        split.setDividerPositions(0.68);
        return split;
    }

    /* ── charts ──────────────────────────────────────────────────────────── */

    private VBox buildCharts() {
        latencySeries.setName("Latency (ms)");
        throughputSeries.setName("Throughput (B/s)");
        lossSeries.setName("Packet Loss (%)");

        LineChart<Number, Number> latencyChart  = makeChart("Latency (ms)",    latencySeries);
        LineChart<Number, Number> throughChart  = makeChart("Throughput (B/s)",throughputSeries);
        LineChart<Number, Number> lossChart     = makeChart("Packet Loss (%)", lossSeries);

        VBox charts = new VBox(8, latencyChart, throughChart, lossChart);
        charts.setPadding(new Insets(10));
        VBox.setVgrow(latencyChart,  Priority.ALWAYS);
        VBox.setVgrow(throughChart,  Priority.ALWAYS);
        VBox.setVgrow(lossChart,     Priority.ALWAYS);
        return charts;
    }

    @SuppressWarnings("unchecked")
    private LineChart<Number, Number> makeChart(String title,
                                                XYChart.Series<Number, Number> series) {
        NumberAxis xAxis = new NumberAxis();
        NumberAxis yAxis = new NumberAxis();
        xAxis.setAutoRanging(true);
        xAxis.setLabel("Session");
        yAxis.setAutoRanging(true);

        LineChart<Number, Number> chart = new LineChart<>(xAxis, yAxis,
                FXCollections.observableArrayList(series));
        chart.setTitle(title);
        chart.setAnimated(false);
        chart.setCreateSymbols(false);
        chart.setLegendVisible(false);
        chart.getStyleClass().add("pqc-chart");
        return chart;
    }

    /* ── status panel ────────────────────────────────────────────────────── */

    private VBox buildStatusPanel() {
        VBox panel = new VBox(12);
        panel.setPadding(new Insets(16));
        panel.getStyleClass().add("status-panel");

        panel.getChildren().addAll(
                sectionLabel("Current Session"),
                statRow("AI Threat",    lblAiDecision),
                statRow("Kyber Level",  lblKyberLevel),
                statRow("Active Path",  lblActivePath),
                new Separator(),
                sectionLabel("Aggregate (last 50)"),
                statRow("Sessions",     lblSessions),
                statRow("Avg Latency",  lblAvgLatency),
                statRow("Avg Throughput", lblAvgThrput),
                statRow("Dominant Mode",  lblDomMode)
        );
        return panel;
    }

    private Label sectionLabel(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("section-label");
        return l;
    }

    private HBox statRow(String key, Label valueLabel) {
        Label keyLabel = new Label(key + ":");
        keyLabel.getStyleClass().add("stat-key");
        valueLabel.getStyleClass().add("stat-value");
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        return new HBox(4, keyLabel, spacer, valueLabel);
    }

    /* ── events table ────────────────────────────────────────────────────── */

    @SuppressWarnings("unchecked")
    private TitledPane buildEventsTable() {
        TableColumn<PathEventRow, String> timeCol  = new TableColumn<>("Time");
        TableColumn<PathEventRow, String> fromCol  = new TableColumn<>("From");
        TableColumn<PathEventRow, String> toCol    = new TableColumn<>("To");
        TableColumn<PathEventRow, String> reasonCol= new TableColumn<>("Reason");

        timeCol.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().time()));
        fromCol.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().from()));
        toCol.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().to()));
        reasonCol.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().reason()));

        timeCol.setPrefWidth(160); fromCol.setPrefWidth(130);
        toCol.setPrefWidth(130);   reasonCol.setPrefWidth(200);

        TableView<PathEventRow> table = new TableView<>(eventRows);
        table.getColumns().addAll(timeCol, fromCol, toCol, reasonCol);
        table.setPrefHeight(160);
        table.setPlaceholder(new Label("No path events yet"));

        TitledPane pane = new TitledPane("Path Failover Events", table);
        pane.setCollapsible(false);
        return pane;
    }

    /* ══════════════════════════════════════════════════════════════════════
     * Polling
     * ══════════════════════════════════════════════════════════════════════ */

    public void startPolling() {
        poller = new Timeline(new KeyFrame(
                Duration.seconds(POLL_SECS), e -> poll()));
        poller.setCycleCount(Animation.INDEFINITE);
        poller.play();
    }

    public void shutdown() {
        if (poller != null) poller.stop();
    }

    private void poll() {
        fetchStatus();
        fetchMetrics();
        fetchPathEvents();
    }

    /* ── fetch /api/status ───────────────────────────────────────────────── */

    private void fetchStatus() {
        try {
            String body = get(BASE_URL + "/status");
            JsonObject obj = gson.fromJson(body, JsonObject.class);

            Platform.runLater(() -> {
                lblConnection.setText("● Connected");
                lblConnection.setTextFill(Color.LIMEGREEN);

                setText(lblAiDecision, obj, "currentAiDecision");
                setText(lblKyberLevel, obj, "currentKyberLevel");
                setText(lblActivePath, obj, "currentActivePath");
                lblSessions.setText(obj.has("totalSessions")
                        ? obj.get("totalSessions").getAsString() : "—");
                lblAvgLatency.setText(obj.has("avgLatencyMs")
                        ? String.format("%.1f ms", obj.get("avgLatencyMs").getAsDouble()) : "—");
                lblAvgThrput.setText(obj.has("avgThroughputBps")
                        ? String.format("%.0f B/s", obj.get("avgThroughputBps").getAsDouble()) : "—");
                setText(lblDomMode, obj, "dominantAiMode");

                /* colour-code AI threat level */
                String ai = lblAiDecision.getText();
                lblAiDecision.setTextFill(
                        "HIGH".equals(ai)   ? Color.TOMATO :
                        "MEDIUM".equals(ai) ? Color.ORANGE :
                                              Color.LIMEGREEN);
            });
        } catch (Exception ex) {
            Platform.runLater(() -> {
                lblConnection.setText("● Disconnected");
                lblConnection.setTextFill(Color.TOMATO);
            });
        }
    }

    /* ── fetch /api/metrics/recent ───────────────────────────────────────── */

    private void fetchMetrics() {
        try {
            String body = get(BASE_URL + "/metrics/recent?n=" + CHART_POINTS);
            JsonArray arr = gson.fromJson(body, JsonArray.class);

            List<double[]> points = new ArrayList<>();
            for (JsonElement el : arr) {
                JsonObject m = el.getAsJsonObject();
                points.add(new double[]{
                        m.has("latencyMs")     ? m.get("latencyMs").getAsDouble()     : 0,
                        m.has("throughputBps") ? m.get("throughputBps").getAsDouble() : 0,
                        m.has("packetLossPct") ? m.get("packetLossPct").getAsDouble() : 0,
                });
            }
            Collections.reverse(points);   /* oldest first */

            Platform.runLater(() -> {
                latencySeries.getData().clear();
                throughputSeries.getData().clear();
                lossSeries.getData().clear();
                int x = chartX - points.size();
                for (double[] p : points) {
                    latencySeries.getData().add(new XYChart.Data<>(x, p[0]));
                    throughputSeries.getData().add(new XYChart.Data<>(x, p[1]));
                    lossSeries.getData().add(new XYChart.Data<>(x, p[2]));
                    x++;
                }
                chartX++;
            });
        } catch (Exception ignored) {}
    }

    /* ── fetch /api/path-events/recent ──────────────────────────────────── */

    private void fetchPathEvents() {
        try {
            String body = get(BASE_URL + "/path-events/recent?n=20");
            JsonArray arr = gson.fromJson(body, JsonArray.class);

            List<PathEventRow> rows = new ArrayList<>();
            for (JsonElement el : arr) {
                JsonObject e = el.getAsJsonObject();
                long ts = e.has("timestamp") ? e.get("timestamp").getAsLong() : 0;
                rows.add(new PathEventRow(
                        ts == 0 ? "—" : new java.util.Date(ts).toString(),
                        e.has("fromPath") ? e.get("fromPath").getAsString() : "—",
                        e.has("toPath")   ? e.get("toPath").getAsString()   : "—",
                        e.has("reason")   ? e.get("reason").getAsString()   : "—"
                ));
            }

            Platform.runLater(() -> {
                eventRows.setAll(rows);
            });
        } catch (Exception ignored) {}
    }

    /* ── HTTP helper ─────────────────────────────────────────────────────── */

    private String get(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    /* ── tiny helpers ────────────────────────────────────────────────────── */

    private void setText(Label label, JsonObject obj, String key) {
        label.setText(obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString() : "—");
    }

    public record PathEventRow(String time, String from, String to, String reason) {}
}
