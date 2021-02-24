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
        List<DoctorDiagnosisResult> problems = new ArrayList<>();

        NetworkConfiguration currentNetworkConfiguration = networkServices.getCurrentNetworkConfiguration();
        if (currentNetworkConfiguration.isAutomatic()) {
            problems.add(new DoctorDiagnosisResult(HINT, EVERYONE, "You are using the automatic network mode. It may cause problems."));
        } else {
            problems.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "You are using a good network mode"));
        }

        if (sslService.isSslEnabled()) {
            problems.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "You have HTTPS enabled"));

            problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The Auto Trust App is not enabled"));

            problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The DDGTR blocker list is not enabled"));

            problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "FAKE: The cookie blocker list is not enabled"));

            problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "FAKE: IPv6 seems to be enabled in your network. Please turn it off as you are using HTTPS"));

        } else {
            problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EXPERT, "HTTPS is not enabled. You will get better tracking protection with it"));
        }

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Automatic mode is not enabled for device XY"));

        if (deviceFactory.isAutoEnableNewDevices()) {
            problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "eBlocker will be automatically enabled for new devices. This may cause trouble when a new device is not ready for eBlocker"));
        } else {
            problems.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "eBlocker will not be automatically enabled for new devices, so you don't run into trouble during setup. Don't forget to enable new devices manually..."));
        }

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled globally for Domain Blocking"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled globally for Pattern Blocking"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Malware & Phishing Blocker list is not enabled for device XY"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "FAKE: Control bar is not auto-configured for device XY"));

        if (!automaticUpdater.isActivated()) {
            problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Automatic updates are disabled"));
        }

        LocalDateTime lastUpdateTime = debianUpdater.getLastUpdateTime();
        if (lastUpdateTime == null) {
            problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "System updates never ran"));
        } else if (LocalDateTime.now().minusDays(2).isBefore(lastUpdateTime)) {
            problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "Last system update is older than two days : " + lastUpdateTime));
        } else {
            problems.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "System updates are okay"));
        }

        problems.add(new DoctorDiagnosisResult(ANORMALY, EVERYONE, "FAKE: Child XY has no restrictions"));

        if (hasNonGoodNameServers()) {
            problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "You have name servers with non-good rating"));
        } else {
            problems.add(new DoctorDiagnosisResult(GOOD, EVERYONE, "Your name servers look good"));
        }
        return problems;
    }

    private boolean hasNonGoodNameServers() {
        List<NameServerStats> nameServerStats = dnsStatisticsService.getResolverStatistics("custom",
                ZonedDateTime.now().minusHours(24).toInstant()).getNameServerStats();
        // TODO: deal with empty stat list
        return nameServerStats.stream().anyMatch(nss -> !nss.getRating().equals(DnsRating.GOOD));
    }
}
