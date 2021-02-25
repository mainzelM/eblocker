package org.eblocker.server.http.service;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.eblocker.server.common.data.DeviceFactory;
import org.eblocker.server.common.data.DoctorDiagnosisResult;
import org.eblocker.server.common.data.NetworkConfiguration;
import org.eblocker.server.common.data.dns.DnsRating;
import org.eblocker.server.common.data.dns.NameServerStats;
import org.eblocker.server.common.network.NetworkServices;
import org.eblocker.server.common.ssl.SslService;
import org.eblocker.server.common.update.AutomaticUpdater;
import org.eblocker.server.common.update.DebianUpdater;

import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EVERYONE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EXPERT;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.ANORMALY;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.FAILED_PROBE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.GOOD;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.HINT;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.RECOMMENDATION_NOT_FOLLOWED;

@Singleton
public class DoctorService {

    private final NetworkServices networkServices;
    private final SslService sslService;
    private final AutomaticUpdater automaticUpdater;
    private final DebianUpdater debianUpdater;
    private final DnsStatisticsService dnsStatisticsService;
    private final DeviceFactory deviceFactory;

    @Inject
    public DoctorService(NetworkServices networkServices, SslService sslService, AutomaticUpdater automaticUpdater, DebianUpdater debianUpdater, DnsStatisticsService dnsStatisticsService, DeviceFactory deviceFactory) {
        this.networkServices = networkServices;
        this.sslService = sslService;
        this.automaticUpdater = automaticUpdater;
        this.debianUpdater = debianUpdater;
        this.dnsStatisticsService = dnsStatisticsService;
        this.deviceFactory = deviceFactory;
    }

    public List<DoctorDiagnosisResult> runDiagnosis() {
        List<DoctorDiagnosisResult> diagnoses = new ArrayList<>();

        NetworkConfiguration currentNetworkConfiguration = networkServices.getCurrentNetworkConfiguration();
        if (currentNetworkConfiguration.isAutomatic()) {
            diagnoses.add(new DoctorDiagnosisResult(HINT, EVERYONE, "You are using the automatic network mode. It may cause problems."));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "You are using a good network mode"));
        }

        if (pingHost(4, "eblocker.org")) {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "Your eBlocker can reach the internet via ICMP"));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "Your eBlocker cannot reach the internet"));
        }

        if (sslService.isSslEnabled()) {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "You have HTTPS enabled"));

            diagnoses.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The Auto Trust App is not enabled"));

            diagnoses.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The DDGTR blocker list is not enabled"));

            diagnoses.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The cookie blocker list is not enabled"));

            if (pingHost(6, "google.com")) {
                diagnoses.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "You have IPv6 enabled. That will bypass the tracking of eBlocker"));
            } else {
                diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "You have IPv6 disabled"));
            }

        } else {
            diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EXPERT, "HTTPS is not enabled. You will get better tracking protection with it"));
        }

        diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Automatic mode is not enabled for device XY"));

        if (deviceFactory.isAutoEnableNewDevices()) {
            diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "eBlocker will be automatically enabled for new devices. This may cause trouble when a new device is not ready for eBlocker"));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "eBlocker will not be automatically enabled for new devices, so you don't run into trouble during setup. Don't forget to enable new devices manually..."));
        }

        diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled globally for Domain Blocking"));

        diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled globally for Pattern Blocking"));

        diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled for device XY"));

        diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Control bar is not auto-configured for device XY"));

        if (automaticUpdater.isActivated()) {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "Your eBlocker is configured to automatically update itself on a daily basis"));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Automatic updates are disabled"));
        }

        LocalDateTime lastUpdateTime = debianUpdater.getLastUpdateTime();
        if (lastUpdateTime == null) {
            diagnoses.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "System updates never ran"));
        } else if (LocalDateTime.now().minusDays(2).isBefore(lastUpdateTime)) {
            diagnoses.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "Last system update is older than two days : " + lastUpdateTime));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "System updates are okay"));
        }

        diagnoses.add(new DoctorDiagnosisResult(ANORMALY, EVERYONE, "FAKE: Child XY has no restrictions"));

        if (hasNonGoodNameServers()) {
            diagnoses.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "You have name servers with non-good rating"));
        } else {
            diagnoses.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "Your name servers look good"));
        }
        return diagnoses;
    }

    private boolean hasNonGoodNameServers() {
        List<NameServerStats> nameServerStats = dnsStatisticsService.getResolverStatistics("custom",
                ZonedDateTime.now().minusHours(24).toInstant()).getNameServerStats();
        // TODO: deal with empty stat list
        return nameServerStats.stream().anyMatch(nss -> !nss.getRating().equals(DnsRating.GOOD));
    }

    private boolean pingHost(int ipVersion, String hostName) {
        String pingCommand = ipVersion == 4 ? "ping" : "ping6";
        ProcessBuilder pb = new ProcessBuilder(pingCommand, "-c", "1", hostName);
        try {
            Process start = pb.start();
            boolean result = start.waitFor(5, TimeUnit.SECONDS);
            return result && start.exitValue() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
