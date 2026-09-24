import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.stream.Collectors;

public class SecurityToolkit {
    public static void main(String[] args) {
        if (args.length == 0) {
            printHelp();
            return;
        }

        try {
            switch (args[0].toLowerCase(Locale.ROOT)) {
                case "password-check":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit password-check <password>");
                        return;
                    }
                    analyzePassword(args[1]);
                    break;

                case "file-permissions":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit file-permissions <path>");
                        return;
                    }
                    checkFilePermissions(Paths.get(args[1]));
                    break;

                case "port-scan":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit port-scan <host> [startPort] [endPort]");
                        return;
                    }
                    int start = 1;
                    int end = 1024;
                    if (args.length >= 3) {
                        start = Integer.parseInt(args[2]);
                    }
                    if (args.length >= 4) {
                        end = Integer.parseInt(args[3]);
                    }
                    scanPorts(args[1], start, end);
                    break;

                case "log-analyzer":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit log-analyzer <logfile>");
                        return;
                    }
                    analyzeLogFile(Paths.get(args[1]));
                    break;

                case "security-audit":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit security-audit <folder-or-file>");
                        return;
                    }
                    auditSecurity(Paths.get(args[1]));
                    break;

                case "report":
                    if (args.length < 2) {
                        System.out.println("Usage: java SecurityToolkit report <folder-or-file> [output-file]");
                        return;
                    }
                    generateReport(Paths.get(args[1]), args.length >= 3 ? Paths.get(args[2]) : Paths.get("security_report.txt"));
                    break;

                default:
                    printHelp();
            }
        } catch (NumberFormatException e) {
            System.out.println("[ERROR] Invalid numeric value provided.");
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void printHelp() {
        System.out.println("Cybersecurity Defensive Toolkit");
        System.out.println("Usage:");
        System.out.println("  java SecurityToolkit password-check <password>");
        System.out.println("  java SecurityToolkit file-permissions <path>");
        System.out.println("  java SecurityToolkit port-scan <host> [startPort] [endPort]");
        System.out.println("  java SecurityToolkit log-analyzer <logfile>");
        System.out.println("  java SecurityToolkit security-audit <folder-or-file>");
        System.out.println("  java SecurityToolkit report <folder-or-file> [output-file]");
    }

    private static void analyzePassword(String password) {
        System.out.println("Password analysis for: " + password.replaceAll(".", "*") + "\n");

        int score = 0;
        List<String> issues = new ArrayList<>();

        if (password == null || password.length() < 8) {
            issues.add("Length under 8 characters");
        } else {
            score += 2;
        }

        if (password.matches(".*[a-z].*")) {
            score += 1;
        } else {
            issues.add("No lowercase letter");
        }

        if (password.matches(".*[A-Z].*")) {
            score += 1;
        } else {
            issues.add("No uppercase letter");
        }

        if (password.matches(".*\\d.*")) {
            score += 1;
        } else {
            issues.add("No number");
        }

        if (password.matches(".*[^A-Za-z0-9].*")) {
            score += 2;
        } else {
            issues.add("No special character");
        }

        if (password.matches(".*(.)\\1{2,}.*")) {
            issues.add("Contains repeated characters");
            score -= 1;
        }

        if (password.toLowerCase(Locale.ROOT).contains("password") ||
            password.toLowerCase(Locale.ROOT).contains("admin") ||
            password.toLowerCase(Locale.ROOT).contains("1234")) {
            issues.add("Contains common weak pattern");
            score -= 2;
        }

        String rating;
        if (score >= 7) {
            rating = "Strong";
        } else if (score >= 5) {
            rating = "Moderate";
        } else {
            rating = "Weak";
        }

        System.out.println("Strength: " + rating);
        System.out.println("Score: " + score + "/9");
        if (issues.isEmpty()) {
            System.out.println("No major issues found.");
        } else {
            System.out.println("Issues:");
            for (String issue : issues) {
                System.out.println(" - " + issue);
            }
        }
    }

    private static void checkFilePermissions(Path path) throws IOException {
        if (!Files.exists(path)) {
            System.out.println("[ERROR] Path does not exist: " + path);
            return;
        }

        System.out.println("File: " + path.toAbsolutePath());
        System.out.println("Type: " + (Files.isDirectory(path) ? "Directory" : "File"));

        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            System.out.println("POSIX permissions: " + PosixFilePermissions.toString(permissions));

            boolean worldWritable = permissions.contains(PosixFilePermission.OTHERS_WRITE);
            boolean groupWritable = permissions.contains(PosixFilePermission.GROUP_WRITE);

            if (worldWritable || groupWritable) {
                System.out.println("[WARNING] File or directory is writable by group or others.");
            } else {
                System.out.println("Permissions look restrictive and safer.");
            }
        } catch (UnsupportedOperationException e) {
            System.out.println("POSIX permissions are not supported on this operating system.");
            System.out.println("Read: " + Files.isReadable(path));
            System.out.println("Write: " + Files.isWritable(path));
            System.out.println("Execute: " + Files.isExecutable(path));
        }
    }

    private static void scanPorts(String host, int start, int end) {
        if (start > end) {
            int temp = start;
            start = end;
            end = temp;
        }

        System.out.println("Scanning host: " + host + " from port " + start + " to " + end + "\n");
        List<Integer> openPorts = new ArrayList<>();

        for (int port = start; port <= end; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 300);
                openPorts.add(port);
                System.out.println("OPEN port " + port);
            } catch (IOException ignored) {
                // Connection failed, port is closed
            }
        }

        if (openPorts.isEmpty()) {
            System.out.println("No open ports detected in the requested range.");
        }
    }

    private static void analyzeLogFile(Path logFile) throws IOException {
        if (!Files.exists(logFile)) {
            System.out.println("[ERROR] Log file not found: " + logFile);
            return;
        }

        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        Map<String, Integer> errorCounts = new HashMap<>();
        int failedLogins = 0;
        int suspiciousEntries = 0;

        for (String line : lines) {
            String lower = line.toLowerCase(Locale.ROOT);

            if (lower.contains("failed login") || lower.contains("invalid password") || lower.contains("authentication failed")) {
                failedLogins++;
                suspiciousEntries++;
                errorCounts.merge("Failed login", 1, Integer::sum);
            }

            if (lower.contains("sql injection") || lower.contains("command injection") || lower.contains("xss") || lower.contains("unauthorized") || lower.contains("root") || lower.contains("privilege escalation")) {
                suspiciousEntries++;
                errorCounts.merge("Security alert", 1, Integer::sum);
            }

            if (lower.contains("exception") || lower.contains("error") || lower.contains("stack trace")) {
                errorCounts.merge("Error", 1, Integer::sum);
            }
        }

        System.out.println("Log analysis for: " + logFile.toAbsolutePath());
        System.out.println("Total lines: " + lines.size());
        System.out.println("Failed login events: " + failedLogins);
        System.out.println("Suspicious entries: " + suspiciousEntries);

        if (errorCounts.isEmpty()) {
            System.out.println("No notable security patterns detected.");
            return;
        }

        System.out.println("Patterns found:");
        for (Map.Entry<String,Integer> entry : errorCounts.entrySet()) {
            System.out.println(" - " + entry.getKey() + ": " + entry.getValue());
        }

        if (failedLogins >= 5) {
            System.out.println("[WARNING] Multiple failed login attempts detected. Possible brute force activity.");
        }
    }

    private static void auditSecurity(Path target) throws IOException {
        if (!Files.exists(target)) {
            System.out.println("[ERROR] Target does not exist: " + target);
            return;
        }

        List<String> findings = new ArrayList<>();
        List<Path> files = new ArrayList<>();
        Files.walk(target)
            .filter(Files::isRegularFile)
            .forEach(files::add);

        files.sort(Comparator.naturalOrder());

        for (Path file : files) {
            String lowerName = file.getFileName().toString().toLowerCase(Locale.ROOT);
            if (lowerName.endsWith(".class") || lowerName.endsWith(".jar") || lowerName.endsWith(".zip") || lowerName.endsWith(".exe") || lowerName.endsWith(".dll")) {
                continue;
            }

            try {
                String content = Files.readString(file, StandardCharsets.UTF_8);
                List<String> lines = Arrays.asList(content.split("\\R", -1));

                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    String lc = line.toLowerCase(Locale.ROOT);

                    if (lc.contains("password") || lc.contains("passwd") || lc.contains("secret") || lc.contains("api_key") || lc.contains("privatekey") || lc.contains("token")) {
                        if (line.matches(".*[:=].*['\"][^'\"]+['\"]")) {
                            findings.add("HIGH | Hardcoded secret | " + file + " | line " + (i + 1));
                        }
                    }

                    if (lc.contains("executequery") || lc.contains("executeupdate") || lc.contains("statement") || lc.contains("select") && lc.contains("+") && (lc.contains("user") || lc.contains("input"))) {
                        findings.add("HIGH | SQL injection risk | " + file + " | line " + (i + 1));
                    }

                    if (lc.contains("runtime.getruntime") || lc.contains("processbuilder") || lc.contains("system.command") || lc.contains("os.system")) {
                        findings.add("HIGH | Command injection risk | " + file + " | line " + (i + 1));
                    }

                    if (lc.contains("md5") || lc.contains("sha1") || lc.contains("des") || lc.contains("rc4")) {
                        findings.add("MEDIUM | Weak cryptography | " + file + " | line " + (i + 1));
                    }

                    if (lc.contains("new random") || lc.contains("math.random")) {
                        findings.add("MEDIUM | Weak randomness | " + file + " | line " + (i + 1));
                    }

                    if (lc.contains("filewriter") || lc.contains("fileoutputstream") || lc.contains("files.write") || lc.contains("files.writestring")) {
                        findings.add("MEDIUM | Unsafe file write | " + file + " | line " + (i + 1));
                    }
                }
            } catch (IOException ignored) {
                // Ignore binary or unreadable files
            }
        }

        if (findings.isEmpty()) {
            System.out.println("No known security findings detected in: " + target);
            return;
        }

        System.out.println("Security audit results for: " + target + "\n");
        for (String finding : findings) {
            System.out.println(finding);
        }
    }

    private static void generateReport(Path target, Path outputFile) throws IOException {
        if (!Files.exists(target)) {
            System.out.println("[ERROR] Target does not exist: " + target);
            return;
        }

        StringBuilder report = new StringBuilder();
        report.append("Security Report\n");
        report.append("Generated: ").append(new Date()).append("\n");
        report.append("Target: ").append(target.toAbsolutePath()).append("\n\n");

        // File permission summary
        List<String> permissionInfo = new ArrayList<>();
        Files.walk(target)
            .filter(Files::isRegularFile)
            .forEach(path -> {
                try {
                    if (Files.getPosixFilePermissions(path).contains(PosixFilePermission.OTHERS_WRITE) ||
                        Files.getPosixFilePermissions(path).contains(PosixFilePermission.GROUP_WRITE)) {
                        permissionInfo.add("WRITEABLE | " + path.toAbsolutePath());
                    }
                } catch (UnsupportedOperationException | IOException ignored) {
                    // Not supported on this OS or inaccessible
                }
            });

        if (permissionInfo.isEmpty()) {
            report.append("Permissions check: No group/world writable files found.\n");
        } else {
            report.append("Permissions check:\n");
            for (String item : permissionInfo) {
                report.append(" - ").append(item).append("\n");
            }
        }

        // Security audit summary
        List<String> findings = new ArrayList<>();
        Files.walk(target)
            .filter(Files::isRegularFile)
            .forEach(file -> {
                try {
                    String content = Files.readString(file, StandardCharsets.UTF_8);
                    String lower = content.toLowerCase(Locale.ROOT);
                    if (lower.contains("password") || lower.contains("passwd") || lower.contains("api_key") || lower.contains("secret") || lower.contains("token")) {
                        findings.add("Potential secret exposure in " + file);
                    }
                    if (lower.contains("md5") || lower.contains("sha1") || lower.contains("des") || lower.contains("rc4")) {
                        findings.add("Weak crypto usage in " + file);
                    }
                    if (lower.contains("runtime.getruntime") || lower.contains("processbuilder") || lower.contains("os.system")) {
                        findings.add("Command execution pattern in " + file);
                    }
                } catch (IOException ignored) {
                    // Skip unreadable files
                }
            });

        report.append("\nSecurity findings:\n");
        if (findings.isEmpty()) {
            report.append("No obvious findings detected.\n");
        } else {
            for (String item : findings) {
                report.append(" - ").append(item).append("\n");
            }
        }

        Files.writeString(outputFile, report.toString(), StandardCharsets.UTF_8);
        System.out.println("Security report created: " + outputFile.toAbsolutePath());
    }
}
