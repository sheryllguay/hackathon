package com.ucsi.cerberus.model;

/**
 * Report type: a single threat indicator (IOC).
 */
public class ThreatIndicator extends Report {

    private String indicatorType;
    private String value;

    public String getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(String indicatorType) {
        this.indicatorType = indicatorType;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String kind() {
        return "threat-indicator";
    }
}
