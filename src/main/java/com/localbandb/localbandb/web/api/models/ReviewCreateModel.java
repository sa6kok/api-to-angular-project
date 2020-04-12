package com.localbandb.localbandb.web.api.models;

public class ReviewCreateModel {

    private Integer level;

    private String description;

    public ReviewCreateModel() {
    }

    public Integer getLevel() {
        return level;
    }

    public void setLevel(Integer level) {
        this.level = level;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
