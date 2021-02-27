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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EVERYONE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EXPERT;
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

        diagnoses.add(networkModeCheck());

        diagnoses.add(ipv4Ping());

        diagnoses.addAll(dnsLookupCheck());

        diagnoses.addAll(httpsRelatedChecks());

        //diagnoses.add(recommendationNotFollowedEveryone("FAKE: Automatic mode is not enabled for device XY"));

        diagnoses.add(autoEnableNewDevicesCheck());

        //diagnoses.add(recommendationNotFollowedEveryone("FAKE: Malware & Phishing Blocker list is not enabled globally for Domain Blocking"));

        //diagnoses.add(recommendationNotFollowedEveryone("FAKE: Malware & Phishing Blocker list is not enabled globally for Pattern Blocking"));

        //diagnoses.add(recommendationNotFollowedEveryone("FAKE: Malware & Phishing Blocker list is not enabled for device XY"));

        //diagnoses.add(recommendationNotFollowedEveryone("FAKE: Control bar is not auto-configured for device XY"));

        diagnoses.addAll(autoUpdateChecks());

        //diagnoses.add(new DoctorDiagnosisResult(ANORMALY, EVERYONE, "FAKE: Child XY has no restrictions"));

        if (hasNonGoodNameServers()) {
            diagnoses.add(failedProbe("You have name servers with non-good rating"));
        } else {
            diagnoses.add(goodForEveryone("Your name servers look good"));
        }
        return diagnoses;
    }

    private DoctorDiagnosisResult networkModeCheck() {
        NetworkConfiguration currentNetworkConfiguration = networkServices.getCurrentNetworkConfiguration();
        if (currentNetworkConfiguration.isAutomatic()) {
            return new DoctorDiagnosisResult(HINT, EVERYONE, "You are using the automatic network mode. It may cause problems.");
        } else {
            return goodForEveryone("You are using a good network mode");
        }
    }

    private List<DoctorDiagnosisResult> autoUpdateChecks() {
        List<DoctorDiagnosisResult> diagnoses = new ArrayList<>();
        if (automaticUpdater.isActivated()) {
            diagnoses.add(goodForEveryone("Your eBlocker is configured to automatically update itself on a daily basis"));
        } else {
            diagnoses.add(recommendationNotFollowedEveryone("Automatic updates are disabled"));
        }

        LocalDateTime lastUpdateTime = debianUpdater.getLastUpdateTime();
        if (lastUpdateTime == null) {
            diagnoses.add(failedProbe("System updates never ran"));
        } else if (LocalDateTime.now().minusDays(2).isBefore(lastUpdateTime)) {
            diagnoses.add(failedProbe("Last system update is older than two days : " + lastUpdateTime));
        } else {
            diagnoses.add(goodForEveryone("System updates are okay"));
        }
        return diagnoses;
    }

    private List<DoctorDiagnosisResult> httpsRelatedChecks() {
        List<DoctorDiagnosisResult> diagnoses = new ArrayList<>();
        if (sslService.isSslEnabled()) {
            diagnoses.add(goodForEveryone("You have HTTPS enabled"));

            //diagnoses.add(hintForExpert("FAKE: The Auto Trust App is not enabled"));

            //diagnoses.add(hintForExpert("FAKE: The DDGTR blocker list is not enabled"));

            //diagnoses.add(hintForExpert("FAKE: The cookie blocker list is not enabled"));

            ipv6Check(diagnoses);
        } else {
            diagnoses.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EXPERT, "HTTPS is not enabled. You will get better tracking protection with it"));
        }
        return diagnoses;
    }

    private DoctorDiagnosisResult autoEnableNewDevicesCheck() {
        if (deviceFactory.isAutoEnableNewDevices()) {
            return recommendationNotFollowedEveryone("eBlocker will be automatically enabled for new devices. This may cause trouble when a new device is not ready for eBlocker");
        } else {
            return goodForEveryone("eBlocker will not be automatically enabled for new devices, so you don't run into trouble during setup. Don't forget to enable new devices manually...");
        }
    }

    private List<DoctorDiagnosisResult> dnsLookupCheck() {
        try {
            //noinspection ResultOfMethodCallIgnored
            InetAddress.getByName("eblocker.org");
            return Collections.singletonList(goodForEveryone("The eBlocker itself can resolve DNS names"));
        } catch (UnknownHostException e) {
            return Collections.singletonList(failedProbe("The eBlocker itself cannot resolve DNS names. Check your DNS settings"));
        }
    }

    private DoctorDiagnosisResult ipv4Ping() {
        if (pingHost(4, "1.1.1.1")) {
            return goodForEveryone("Your eBlocker can reach the internet via ICMP/ping");
        } else {
            return failedProbe("Your eBlocker cannot reach the internet via ICMP/ping");
        }
    }

    private void ipv6Check(List<DoctorDiagnosisResult> diagnoses) {
        if (pingHost(6, "ipv6-test.com")) {
            diagnoses.add(failedProbe("Your network can access the internet via IPv6. That will bypass the tracking of eBlocker if HTTPS support is enabled."));
        } else {
            diagnoses.add(goodForEveryone("Your network cannot access the internet via IPv6. This is good news as the eBlocker does not support IPv6 yet."));
        }
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
            boolean finished = start.waitFor(5, TimeUnit.SECONDS);
            return finished && start.exitValue() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private DoctorDiagnosisResult failedProbe(String message) {
        return new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, message);
    }

    private DoctorDiagnosisResult goodForEveryone(String message) {
        return new DoctorDiagnosisResult(GOOD, EVERYONE, message);
    }

    private DoctorDiagnosisResult recommendationNotFollowedEveryone(String message) {
        return new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, message);
    }

    private DoctorDiagnosisResult hintForExpert(String message) {
        return new DoctorDiagnosisResult(HINT, EXPERT, message);
    }

}
