package org.eblocker.server.http.service;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.eblocker.server.common.data.DoctorDiagnosisResult;
import org.eblocker.server.common.data.NetworkConfiguration;
import org.eblocker.server.common.network.NetworkServices;

import java.util.ArrayList;
import java.util.List;

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
            problems.add(new DoctorDiagnosisResult(DoctorDiagnosisResult.Severity.HINT, DoctorDiagnosisResult.Audience.EVERYONE, "You are using the automatic network mode. It may cause problems."));
        }
        return problems;
    }
}
