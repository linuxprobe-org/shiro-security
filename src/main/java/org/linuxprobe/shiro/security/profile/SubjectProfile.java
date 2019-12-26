package org.linuxprobe.shiro.security.profile;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class SubjectProfile implements Serializable {
    private static final long serialVersionUID = -8555709398975125873L;
    private String id;
    private Map<String, Object> attributes = new HashMap<>();
    private String clientName;
}
