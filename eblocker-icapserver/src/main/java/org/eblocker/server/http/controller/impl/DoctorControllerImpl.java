package org.eblocker.server.http.controller.impl;

import com.google.inject.Inject;
import org.eblocker.server.http.controller.DoctorController;
import org.restexpress.Request;
import org.restexpress.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

public class DoctorControllerImpl implements DoctorController {

    private static final Logger log = LoggerFactory.getLogger(DoctorControllerImpl.class);

    @Inject
    public DoctorControllerImpl() {
    }

    @Override
    public List<String> runDiagnosis(Request request, Response response) {
        return Arrays.asList("Diag 1", "Diag 2");
    }
}
