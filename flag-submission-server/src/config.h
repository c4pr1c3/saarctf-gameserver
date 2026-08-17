#ifndef FLAG_SUBMISSION_SERVER_CONFIG_H
#define FLAG_SUBMISSION_SERVER_CONFIG_H

#include <string>
#include <cstdint>

class Config {
public:
	static void load();

	static void load(const std::string& filename);

	static void loadFromEnv();

	static const char *getPostgresConnectionString();

	static std::string getRedisHost();

	static int getRedisPort();

	static int getRedisDB();

	static std::string getRedisPassword();

	static unsigned char hmac_secret_key[32];

	// Effective key actually used for flag MACs: the base key (hmac_secret_key)
	// folded with the per-match secret from Redis ("secrets:flag_key_match"), see
	// flagchecker.cpp / apply_match_flag_key. Equals hmac_secret_key as long as no
	// per-match secret is known. NOTE for tests: if you overwrite hmac_secret_key
	// directly, sync this field as well.
	static unsigned char hmac_effective_key[32];

	static std::string flagPrefix;

	static int flagRoundsValid;

	// NOP team id. -1 = disabled (no NOP team configured).
	// NOTE: 0 is a VALID team id here — a deployment may legitimately assign
	// the NOP team id 0, so never use truthiness (`if (nopTeamId)`) to test
	// whether a NOP team is configured; use `nopTeamId >= 0`.
	static int nopTeamId;

	static uint16_t getTeamIdFromIp(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3);
};

#endif //FLAG_SUBMISSION_SERVER_CONFIG_H
