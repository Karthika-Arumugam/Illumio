package test;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.Before;
import org.junit.Test;

import core.Firewall;

import java.io.IOException;

public class Test_accept_packet {

	Firewall firewall;

	@Before
	public void setUp() throws IOException {
		firewall = new Firewall("test.csv");
	}

	@Test
	public void test1() {
		assertEquals(true, firewall.accept_packet("outbound", "udp", 1014, "52.12.48.92"));
	}

	@Test
	public void test2() {
		assertEquals(true, firewall.accept_packet("inbound", "tcp", 53, "192.188.2.5"));
	}

	@Test
	public void test3() {
		assertEquals(false, firewall.accept_packet("outbound", "tcp", 100, "192.17.10.2"));
	}

	@Test
	public void test4() {
		assertEquals(false, firewall.accept_packet("inbound", "udp", 10034, "171.22.50.92"));
	}
}
