package com.fivucsas.identity.application.port.input;

/** ROOT-only export of every stored device benchmark run. */
public interface ExportDevbenchRunsUseCase {

    /** JSON array of run documents, oldest first, each with {@code id} and {@code receivedAt} added. */
    String exportJson();

    /** One flat row per run, same columns as the earlier artifact CSV plus {@code id} and {@code receivedAt}. */
    String exportCsv();
}
