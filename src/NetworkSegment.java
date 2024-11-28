public class NetworkSegment {
    private String segmentName;
    private Set<String> allowedIPs;

    public NetworkSegment(String segmentName) {
        this.segmentName = segmentName;
        this.allowedIPs = new HashSet<>();
    }

    public void addAllowedIP(String ip) {
        allowedIPs.add(ip);
    }

    public void removeAllowedIP(String ip) {
        allowedIPs.remove(ip);
    }

    public boolean isIPAllowed(String ip) {
        return allowedIPs.contains(ip);
    }

    public String getSegmentName() {
        return segmentName;
    }
}
