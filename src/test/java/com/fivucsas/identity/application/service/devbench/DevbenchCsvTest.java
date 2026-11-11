package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DevbenchCsvTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void render_WhenRunHasNestedTimings_ShouldFlattenIntoArtifactColumns() throws Exception {
        String doc = "{\"timestamp\":\"2026-11-10T20:00:00Z\",\"deviceLabel\":\"SM-A145F\","
                + "\"browser\":{\"name\":\"Chrome\",\"version\":\"130\"},"
                + "\"screen\":{\"width\":720,\"height\":1600,\"dpr\":2},"
                + "\"timingsMs\":{\"modelFetch_appHost\":4100,\"sessionCreateCold\":900.5,\"firstInference\":300,"
                + "\"warm\":{\"p50\":180.25,\"p95\":210}},\"errors\":[\"a\",\"b\"],\"tool\":\"fivucsas devbench app v1\"}";

        String csv = DevbenchCsv.render(List.of(new DevbenchCsv.Row("id-1", "2026-11-10T20:00:01Z", mapper.readTree(doc))));

        String[] lines = csv.split("\n");
        List<String> header = List.of(lines[0].split(","));
        List<String> row = List.of(lines[1].split(",", -1));
        assertThat(header).startsWith("id", "receivedAt", "timestamp");
        assertThat(row.get(header.indexOf("p50"))).isEqualTo("180.25");
        assertThat(row.get(header.indexOf("browser"))).isEqualTo("Chrome 130");
        assertThat(row.get(header.indexOf("screen"))).isEqualTo("720x1600@2");
        assertThat(row.get(header.indexOf("modelFetchMs"))).isEqualTo("4100");
        assertThat(row.get(header.indexOf("errors"))).isEqualTo("a; b");
        assertThat(row.get(header.indexOf("participant"))).isEmpty();
    }

    @Test
    void cell_WhenValueLooksLikeFormula_ShouldNeutraliseIt() {
        assertThat(DevbenchCsv.cell("=HYPERLINK(\"x\")")).isEqualTo("\"'=HYPERLINK(\"\"x\"\")\"");
        assertThat(DevbenchCsv.cell("@SUM(A1)")).isEqualTo("'@SUM(A1)");
        assertThat(DevbenchCsv.cell("-12.5")).isEqualTo("-12.5");
    }

    @Test
    void cell_WhenValueHasCommaOrQuote_ShouldQuote() {
        assertThat(DevbenchCsv.cell("a,b")).isEqualTo("\"a,b\"");
        assertThat(DevbenchCsv.cell("say \"hi\"")).isEqualTo("\"say \"\"hi\"\"\"");
        assertThat(DevbenchCsv.cell(null)).isEmpty();
    }
}
