package com.ucsi.cerberus.service;

import com.ucsi.cerberus.model.User;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory authentication and session state.
 *
 * <p>Sessions live in a process-local map, so all state is confined to the
 * running instance and is cleared on restart.
 *
 * <p>Seeds a single portal user and issues opaque session tokens used to
 * authenticate subsequent requests.
 */
public class SessionService {

    private static final SecureRandom RNG = new SecureRandom();

    private final Map<String, User> users = new ConcurrentHashMap<>();
    /** token -> username */
    private final Map<String, String> sessions = new ConcurrentHashMap<>();

    public SessionService() {
        users.put("analyst", new User("analyst", "cerberus123"));
    }

    /** @return a new session token on success, or {@code null} on bad creds. */
    public String login(String username, String password) {
        if (username == null || password == null) {
            return null;
        }
        User u = users.get(username);
        if (u == null || !u.getPassword().equals(password)) {
            return null;
        }
        byte[] raw = new byte[24];
        RNG.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        sessions.put(token, username);
        return token;
    }

    public boolean isValid(String token) {
        return token != null && sessions.containsKey(token);
    }

    public String usernameFor(String token) {
        return sessions.get(token);
    }
}
