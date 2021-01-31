package org.eblocker.server.http.service;

import com.google.inject.Inject;
import com.google.inject.Singleton;
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

    public List<String> runDiagnosis() {
        List<String> problems = new ArrayList<>();

        NetworkConfiguration currentNetworkConfiguration = networkServices.getCurrentNetworkConfiguration();
        if (currentNetworkConfiguration.isAutomatic()) {
            problems.add("You are using the automatic mode, consider switching to expert mode");
        }
        return problems;
    }
}
