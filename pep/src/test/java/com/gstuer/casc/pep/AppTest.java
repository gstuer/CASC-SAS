package com.gstuer.casc.pep;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class AppTest {
    @Test
    void testConstructor() {
        App app = new App();
        assertNotNull(app);
    }
}
