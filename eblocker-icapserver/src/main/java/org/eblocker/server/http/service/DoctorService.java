package org.eblocker.server.http.service;

import com.google.inject.Singleton;

import java.util.Arrays;
import java.util.List;

@Singleton
public class DoctorService {
    public List<String> runDiagnosis() {
        return Arrays.asList("Diag 1", "Diag 2", "Diag 3");
    }
}
