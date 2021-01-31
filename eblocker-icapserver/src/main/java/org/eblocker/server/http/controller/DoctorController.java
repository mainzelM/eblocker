package org.eblocker.server.http.controller;

import org.restexpress.Request;
import org.restexpress.Response;

import java.util.List;

public interface DoctorController {
    List<String> runDiagnosis(Request request, Response response);
}
