package org.eblocker.server.http.service;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.eblocker.server.common.data.DoctorDiagnosisResult;
import org.eblocker.server.common.data.NetworkConfiguration;
import org.eblocker.server.common.network.NetworkServices;

import java.util.ArrayList;
import java.util.List;

import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EVERYONE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.EXPERT;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Audience.NOVICE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.ANORMALY;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.FAILED_PROBE;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.HINT;
import static org.eblocker.server.common.data.DoctorDiagnosisResult.Severity.RECOMMENDATION_NOT_FOLLOWED;

@Singleton
public class DoctorService {

    private final NetworkServices networkServices;

    @Inject
    public DoctorService(NetworkServices networkServices) {
        this.networkServices = networkServices;
    }

    public List<DoctorDiagnosisResult> runDiagnosis() {
        List<DoctorDiagnosisResult> problems = new ArrayList<>();

        NetworkConfiguration currentNetworkConfiguration = networkServices.getCurrentNetworkConfiguration();
        if (currentNetworkConfiguration.isAutomatic()) {
            problems.add(new DoctorDiagnosisResult(HINT, EVERYONE, "You are using the automatic network mode. It may cause problems."));
        }

        problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "IPv6 seems to be enabled in your network. Please turn it off if HTTPS is used"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, NOVICE, "HTTPS is not enabled. You will get better tracking protection with it"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Automatic mode is not enabled for device XY"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "eBlocker will be automatically enabled for new devices"));

        problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "The Auto Trust App is not enabled"));

        problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "The DDGTR blocker list is not enabled"));

        problems.add(new DoctorDiagnosisResult(HINT, EXPERT, "The cookie blocker list is not enabled"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Malware & Phishing Blocker list is not enabled globally"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Malware & Phishing Blocker list is not enabled for device XY"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Control bar is not auto-configured for device XY"));

        problems.add(new DoctorDiagnosisResult(RECOMMENDATION_NOT_FOLLOWED, EVERYONE, "Automatic updates are disabled"));

        problems.add(new DoctorDiagnosisResult(FAILED_PROBE, EVERYONE, "Last system update is older than 24 hours"));

        problems.add(new DoctorDiagnosisResult(ANORMALY, EVERYONE, "Child XY has no restrictions"));
        return problems;
    }
}
