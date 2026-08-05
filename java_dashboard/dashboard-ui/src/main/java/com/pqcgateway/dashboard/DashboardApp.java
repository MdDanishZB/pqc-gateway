package com.pqcgateway.dashboard;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class DashboardApp extends Application {

    @Override
    public void start(Stage primaryStage) {
        DashboardController controller = new DashboardController();
        Scene scene = new Scene(controller.buildLayout(), 1100, 720);
        scene.getStylesheets().add(
                getClass().getResource("dashboard.css").toExternalForm());

        primaryStage.setTitle("PQC Gateway — Live Dashboard");
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(e -> controller.shutdown());
        primaryStage.show();

        controller.startPolling();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
