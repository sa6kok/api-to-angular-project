package com.localbandb.localbandb.web.api.models;

public class ReviewViewModel {
    private Integer level;

    private String description;

    public ReviewViewModel() {
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
