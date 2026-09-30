package com.fidd.flowerca.api;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/public")
public class PublicProbeController {

  @GetMapping("/probe")
  public Map<String, String> probe() {
    return Map.of("status", "ok");
  }
}
