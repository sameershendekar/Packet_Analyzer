package dpi;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public String toString() {
        return this.displayName;
    }

    // Map SNI/domain to application type
    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return AppType.UNKNOWN;
        }

        String lowerSni = sni.toLowerCase();

        // Check for known patterns
        // Google (including YouTube subcategories matching Google infrastructure)
        if (lowerSni.contains("google") ||
            lowerSni.contains("gstatic") ||
            lowerSni.contains("googleapis") ||
            lowerSni.contains("ggpht") ||
            lowerSni.contains("gvt1")) {
            return AppType.GOOGLE;
        }

        // YouTube
        if (lowerSni.contains("youtube") ||
            lowerSni.contains("ytimg") ||
            lowerSni.contains("youtu.be") ||
            lowerSni.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }

        // Facebook/Meta
        if (lowerSni.contains("facebook") ||
            lowerSni.contains("fbcdn") ||
            lowerSni.contains("fb.com") ||
            lowerSni.contains("fbsbx") ||
            lowerSni.contains("meta.com")) {
            return AppType.FACEBOOK;
        }

        // Instagram
        if (lowerSni.contains("instagram") ||
            lowerSni.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }

        // WhatsApp
        if (lowerSni.contains("whatsapp") ||
            lowerSni.contains("wa.me")) {
            return AppType.WHATSAPP;
        }

        // Twitter/X
        if (lowerSni.contains("twitter") ||
            lowerSni.contains("twimg") ||
            lowerSni.contains("x.com") ||
            lowerSni.contains("t.co")) {
            return AppType.TWITTER;
        }

        // Netflix
        if (lowerSni.contains("netflix") ||
            lowerSni.contains("nflxvideo") ||
            lowerSni.contains("nflximg")) {
            return AppType.NETFLIX;
        }

        // Amazon
        if (lowerSni.contains("amazon") ||
            lowerSni.contains("amazonaws") ||
            lowerSni.contains("cloudfront") ||
            lowerSni.contains("aws")) {
            return AppType.AMAZON;
        }

        // Microsoft
        if (lowerSni.contains("microsoft") ||
            lowerSni.contains("msn.com") ||
            lowerSni.contains("office") ||
            lowerSni.contains("azure") ||
            lowerSni.contains("live.com") ||
            lowerSni.contains("outlook") ||
            lowerSni.contains("bing")) {
            return AppType.MICROSOFT;
        }

        // Apple
        if (lowerSni.contains("apple") ||
            lowerSni.contains("icloud") ||
            lowerSni.contains("mzstatic") ||
            lowerSni.contains("itunes")) {
            return AppType.APPLE;
        }

        // Telegram
        if (lowerSni.contains("telegram") ||
            lowerSni.contains("t.me")) {
            return AppType.TELEGRAM;
        }

        // TikTok
        if (lowerSni.contains("tiktok") ||
            lowerSni.contains("tiktokcdn") ||
            lowerSni.contains("musical.ly") ||
            lowerSni.contains("bytedance")) {
            return AppType.TIKTOK;
        }

        // Spotify
        if (lowerSni.contains("spotify") ||
            lowerSni.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }

        // Zoom
        if (lowerSni.contains("zoom")) {
            return AppType.ZOOM;
        }

        // Discord
        if (lowerSni.contains("discord") ||
            lowerSni.contains("discordapp")) {
            return AppType.DISCORD;
        }

        // GitHub
        if (lowerSni.contains("github") ||
            lowerSni.contains("githubusercontent")) {
            return AppType.GITHUB;
        }

        // Cloudflare
        if (lowerSni.contains("cloudflare") ||
            lowerSni.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }

        // If SNI is present but not recognized, still mark as TLS/HTTPS
        return AppType.HTTPS;
    }
}
