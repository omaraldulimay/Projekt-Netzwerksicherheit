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

    public void restrictAccess(Set<String> roles, Map<String, Set<String>> rolePermissions) {
        for (String role : roles) {
            Set<String> permissions = rolePermissions.get(role);
            if (permissions != null && !permissions.contains("ACCESS_" + segmentName.toUpperCase())) {
                allowedIPs.clear();
                break;
            }
        }
    }
}
