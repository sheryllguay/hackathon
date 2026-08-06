package com.ucsi.cerberus.model;

/**
 * Report type: an inventory of assets referenced by an incident.
 */
public class AssetInventory extends Report {

    private String owner;
    private int assetCount;

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public int getAssetCount() {
        return assetCount;
    }

    public void setAssetCount(int assetCount) {
        this.assetCount = assetCount;
    }

    @Override
    public String kind() {
        return "asset-inventory";
    }
}
