package dpi;

public class Flow {
    public FiveTuple tuple;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";
    public long packets = 0;
    public long bytes = 0;
    public boolean blocked = false;
}
