#define CATCH_CONFIG_MAIN

#include <thread>
#include <iostream>
#include <chrono>
#include <catch2/catch_test_macros.hpp>
#include <iomanip>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include "../src/config.h"
#include "../src/flagchecker.h"
#include "../src/redis.h"
#include "../src/libraries/base64.h"

using namespace std;


TEST_CASE("force_the_linker_to_do_its_fucking_job") {
	thread t1;
	t1.joinable();
	printf("%p\n", pthread_create);
}


TEST_CASE("IP to Team ID conversion") {
	auto ts = std::chrono::steady_clock::now();

	Config::load("../tests/testconfig.json");
	for (int team_id = 1; team_id <= 10000; team_id++) {
		for (int last_byte = 0; last_byte < 256; last_byte++) {
			auto result = Config::getTeamIdFromIp(127, team_id / 200, team_id % 200, last_byte);
			if (result != team_id) {
				fprintf(stderr, "Expected team %d but got result %d for IP %d.%d.%d.%d",
						team_id, result, 127, team_id / 200, team_id % 200, last_byte);
			}
			REQUIRE(result == team_id);
		}
	}

	for (int team_id = 1; team_id <= 10000; team_id++) {
		for (int last_byte = 0; last_byte < 256; last_byte++) {
			auto result = Config::getTeamIdFromIp(127, 52 + team_id / 200, team_id % 200, last_byte);
			if (result != team_id) {
				fprintf(stderr, "Expected team %d but got result %d for IP %d.%d.%d.%d",
						team_id, result, 127, 52 + team_id / 200, team_id % 200, last_byte);
			}
			REQUIRE(result == team_id);
		}
	}

	auto dt = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - ts);
	auto cnt = 20000 * 256;
	std::cerr << "Time for " << cnt << " conversions: " << dt.count() << " µs" << endl;
	std::cerr << " => " << dt.count() * 1.0 / cnt << " µs/conversion (single-threaded)" << endl;
	std::cerr << " => " << std::fixed << std::setprecision(1) << cnt * 1000000.0 / dt.count() << " conversions/sec (single-threaded)" << endl;
}


TEST_CASE("Check Flag Parser") {
	for (int i = 0; i < sizeof Config::hmac_secret_key; i++)
		Config::hmac_secret_key[i] = 'a';

	SECTION("A simple Flag") {
		const char *flag = "SAAR{OQUHAAwAAAAlt3tF4y_TgZlNX2Yi4hw9}";  // service 12 team 7 tick 1337 payload 0
		FlagFormat binary_flag;
		auto decodeSize = base64_decode((unsigned char *) &flag[5], FLAG_LENGTH_B64, (unsigned char *) &binary_flag);
		REQUIRE(decodeSize == sizeof binary_flag);
		REQUIRE(binary_flag.service_id == 12);
		REQUIRE(binary_flag.team_id == 7);
		REQUIRE(binary_flag.round == 1337);
		REQUIRE(binary_flag.payload == 0);
		REQUIRE(verify_hmac(&binary_flag, &binary_flag.mac, binary_flag.mac));
	}

	SECTION("Negative Numbers / Potential Overflows") {
		const char *flag = "SAAR{x_qtrZWVEQBoxEDkuVt8YreJb7pBW_JH}";  // service 0x9595 team 0xadad tick -1337 payload 17
		FlagFormat binary_flag;
		auto decodeSize = base64_decode((unsigned char *) &flag[5], FLAG_LENGTH_B64, (unsigned char *) &binary_flag);
		REQUIRE(decodeSize == sizeof binary_flag);
		REQUIRE(binary_flag.service_id == 0x9595);
		REQUIRE(binary_flag.team_id == 0xadad);
		REQUIRE(binary_flag.round == (uint16_t) -1337);
		REQUIRE(binary_flag.payload == 17);
		REQUIRE(verify_hmac(&binary_flag, &binary_flag.mac, binary_flag.mac));
	}

	SECTION("Invalid Flag") {
		const char *flag = "SAAR{x_qtrZWVEQBoxEDkuVt8YreJb7pBW_XX}";  // service 0x9595 team 0xadad tick -1337 payload 17
		FlagFormat binary_flag;
		auto decodeSize = base64_decode((unsigned char *) &flag[5], FLAG_LENGTH_B64, (unsigned char *) &binary_flag);
		REQUIRE(decodeSize == sizeof binary_flag);
		REQUIRE(binary_flag.service_id == 0x9595);
		REQUIRE(binary_flag.team_id == 0xadad);
		REQUIRE(binary_flag.round == (uint16_t) -1337);
		REQUIRE(binary_flag.payload == 17);
		REQUIRE(!verify_hmac(&binary_flag, &binary_flag.mac, binary_flag.mac));
	}
}


TEST_CASE("Parse (legacy) Configs") {
	SECTION("testconfig.json") {
		Config::load("../tests/testconfig.json");
		REQUIRE(Config::nopTeamId == 1);
		REQUIRE(Config::flagRoundsValid == 10);
	}

	SECTION("testconfig2.json") {
		Config::load("../tests/testconfig2.json");
		REQUIRE(Config::nopTeamId == 2);
		REQUIRE(Config::flagRoundsValid == 20);
	}

	SECTION("testconfig3.json") {
		Config::load("../tests/testconfig3.json");
		REQUIRE(Config::nopTeamId == 2);
		REQUIRE(Config::flagRoundsValid == 20);
	}

	SECTION("testconfig4.json (nop_team_id = 0)") {
		Config::load("../tests/testconfig4.json");
		REQUIRE(Config::nopTeamId == 0);
		REQUIRE(Config::flagRoundsValid == 10);
	}
}


// Builds a wire-format flag ("SAAR{<base64>}") from the given fields.
// mac is filled with a valid HMAC when valid_mac = true, otherwise zeroed.
static std::string build_flag(uint16_t team_id, uint16_t service_id, uint16_t round, uint16_t payload, bool valid_mac) {
	FlagFormat f{};
	f.round = round;
	f.team_id = team_id;
	f.service_id = service_id;
	f.payload = payload;
	if (valid_mac) {
		create_hmac(&f, &f.mac, f.mac);
	} else {
		memset(f.mac, 0, sizeof f.mac);
	}
	char b64[FLAG_LENGTH_B64 + 1] = {0};
	base64_encode((const unsigned char *) &f, sizeof f, b64);
	return Config::flagPrefix + "{" + std::string(b64, FLAG_LENGTH_B64) + "}";
}

static struct sockaddr_in make_team_addr(const char *ip) {
	struct sockaddr_in addr{};
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &addr.sin_addr);
	return addr;
}


TEST_CASE("NOP team flag rejection") {
	// testconfig4: nop_team_id = 0 (NOP team is team 0), team_range 127.0.0.0/16-ish
	Config::load("../tests/testconfig4.json");
	initModelSizes(255, 10);
	Redis::state = RUNNING;
	Redis::current_round = 1;
	// submitter: team 2 (127.0.2.x per testconfig team_range)
	struct sockaddr_in addr = make_team_addr("127.0.2.9");

	SECTION("flag of NOP team 0 is rejected") {
		std::string flag = build_flag(0, 1, 1, 0, true);
		const char *answer = progress_flag(flag.c_str(), (int) flag.size(), &addr, nullptr);
		REQUIRE(std::string(answer) == "[ERR] Can't submit flag from NOP team\n");
	}

	SECTION("flag of a regular team passes the NOP gate") {
		// invalid MAC => rejected later at the MAC check, proving the NOP check did not fire
		std::string flag = build_flag(7, 1, 1, 0, false);
		const char *answer = progress_flag(flag.c_str(), (int) flag.size(), &addr, nullptr);
		REQUIRE(std::string(answer) == "[ERR] Invalid flag\n");
	}

	SECTION("NOP check disabled when nopTeamId = -1") {
		Config::nopTeamId = -1;
		// round > 0x7fff => rejected as "issued for testing purposes" right after the NOP
		// gate, proving the NOP check stayed inactive for a team_id=0 flag
		std::string flag = build_flag(0, 1, (uint16_t) 0x8000, 0, true);
		const char *answer = progress_flag(flag.c_str(), (int) flag.size(), &addr, nullptr);
		REQUIRE(std::string(answer) == "[ERR] Invalid flag (issued for testing purposes)\n");
	}
}
