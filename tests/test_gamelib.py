import base64
import hashlib
import hmac
import struct
import unittest
from typing import Any
from unittest.mock import patch

from gamelib import gamelib, usernames, Team, ServiceConfig
from tests.utils.base_cases import TestCase


class DummyService(gamelib.ServiceInterface):
    def __init__(self) -> None:
        super().__init__(ServiceConfig(
            service_id=1,
            name='dummy',
            flag_ids=['hex8', 'alphanum5', 'username', 'email', 'pattern:${username}/abc/${alphanum12}'],
            interface_class='',
            interface_file=''
        ))

    def check_integrity(self, team: Team, tick: int) -> None:
        raise NotImplementedError

    def store_flags(self, team: Team, tick: int) -> Any:
        raise NotImplementedError

    def retrieve_flags(self, team: Team, tick: int) -> Any:
        raise NotImplementedError


TEST_TEAMS = [
    gamelib.Team(1, 'Test1', '1.2.3.4'),
    gamelib.Team(2, 'Test2', '1.2.3.8'),
    gamelib.Team(1337, 'Test1337', '127.13.37.1'),
]


class GamelibTestCase(TestCase):
    def test_flag_generator(self) -> None:
        service = DummyService()
        seen_flags: set[str] = set()
        for team in TEST_TEAMS:
            for tick in (1, 2, 0, -1, 1338):
                for payload in (0, 1, 1339):
                    flag: str = service.get_flag(team, tick, payload)
                    self.assertNotIn(flag, seen_flags, f'Flag {flag} duplicated!')
                    seen_flags.add(flag)
                    self.assertTrue(gamelib.get_flag_regex().fullmatch(flag), f'Flag {flag} did not match regex {gamelib.get_flag_regex()}')
                    # parse flag
                    a, b, c, d = service.check_flag(flag)
                    self.assertEqual(a, team.id)
                    self.assertEqual(b, service.id)
                    self.assertEqual(c & 0xffff, tick & 0xffff)  # type: ignore
                    self.assertEqual(d, payload)
                    # check if flag is deterministic
                    for _ in range(3):
                        flag2 = service.get_flag(team, tick, payload)
                        self.assertEqual(flag, flag2)

    def test_flag_ids(self) -> None:
        service = DummyService()
        flag_ids: list[list[str]] = [[], []]
        for i in range(2):
            seen_flag_ids: set[str] = set()
            for team in TEST_TEAMS:
                for round in (1, 2, 0, -1, 1338):
                    for index in range(len(service.config.flag_ids)):
                        flag_id = service.get_flag_id(team, round, index)
                        self.assertNotIn(flag_id, seen_flag_ids, f'Flag ID {flag_id} repeated')
                        seen_flag_ids.add(flag_id)
                        for _ in range(3):
                            flag_id_2 = service.get_flag_id(team, round, index)
                            self.assertEqual(flag_id, flag_id_2, f'Flag ID not deterministic: {flag_id} != {flag_id_2}')
        self.assertListEqual(flag_ids[0], flag_ids[1], 'Multiple runs give different flag ids')


class FakeRedis:
    """Minimal Redis stub: enough for gamelib.get_flag_hmac_key (get + context manager)."""

    def __init__(self, values: dict[str, bytes | None]) -> None:
        self.values = values

    def get(self, key: str | bytes) -> bytes | None:
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        return self.values.get(key)

    def __enter__(self) -> 'FakeRedis':
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class PerMatchFlagKeyTestCase(TestCase):
    SECRET_1 = b'\x11' * 32
    SECRET_2 = b'\x22' * 32

    def setUp(self) -> None:
        # disable the effective-key cache so every get_flag reads the (fake) Redis state
        self._ttl = gamelib.FLAG_KEY_CACHE_TTL
        gamelib.FLAG_KEY_CACHE_TTL = 0.0

    def tearDown(self) -> None:
        gamelib.FLAG_KEY_CACHE_TTL = self._ttl
        # do not leak a fake-derived key into other tests (all tests share one process)
        gamelib._flag_hmac_key_cache = None

    def flag_with_secret(self, secret: bytes | None) -> str:
        fake = FakeRedis({gamelib.PER_MATCH_FLAG_KEY_REDIS_KEY: secret.hex().encode('ascii') if secret else None})
        with patch('gamelib.gamelib.get_redis_connection', return_value=fake):
            return gamelib.get_flag(7, 3, 42, 1)

    def test_cross_match_divergence(self) -> None:
        # same (tick, team, service, payload) but different per-match secret -> different flag values
        flag_match_1 = self.flag_with_secret(self.SECRET_1)
        flag_match_2 = self.flag_with_secret(self.SECRET_2)
        self.assertNotEqual(flag_match_1, flag_match_2)

    def test_same_match_stability(self) -> None:
        # within a match (same secret), flag minting stays deterministic
        flag_1 = self.flag_with_secret(self.SECRET_1)
        flag_2 = self.flag_with_secret(self.SECRET_1)
        self.assertEqual(flag_1, flag_2)
        # ... and matches the derivation HMAC-SHA256(key=base, msg=per-match secret)
        effective = hmac.new(gamelib.config.SECRET_FLAG_KEY, self.SECRET_1, hashlib.sha256).digest()
        data = struct.pack('<HHHH', 42, 7, 3, 1)
        mac = hmac.new(effective, data, hashlib.sha256).digest()[:gamelib.MAC_LENGTH]
        expected = gamelib.config.FLAG_PREFIX + '{' + base64.b64encode(data + mac).replace(b'+', b'-').replace(b'/', b'_').decode('utf-8') + '}'
        self.assertEqual(flag_1, expected)

    def test_absence_falls_back_to_base_key(self) -> None:
        # no per-match secret in Redis -> exactly the legacy behavior (base key)
        flag_absent = self.flag_with_secret(None)
        data = struct.pack('<HHHH', 42, 7, 3, 1)
        mac = hmac.new(gamelib.config.SECRET_FLAG_KEY, data, hashlib.sha256).digest()[:gamelib.MAC_LENGTH]
        expected = gamelib.config.FLAG_PREFIX + '{' + base64.b64encode(data + mac).replace(b'+', b'-').replace(b'/', b'_').decode('utf-8') + '}'
        self.assertEqual(flag_absent, expected)

    def test_check_flag_follows_match_key(self) -> None:
        # a flag minted under SECRET_1 verifies while SECRET_1 is active ...
        fake_1 = FakeRedis({gamelib.PER_MATCH_FLAG_KEY_REDIS_KEY: self.SECRET_1.hex().encode('ascii')})
        service = DummyService()
        with patch('gamelib.gamelib.get_redis_connection', return_value=fake_1):
            flag = service.get_flag(gamelib.Team(7, 'T7', '1.2.3.4'), 42, 1)
            team_id, service_id, tick, payload = service.check_flag(flag)
            self.assertEqual((team_id, service_id, tick, payload), (7, 1, 42, 1))
        # ... and stops verifying once the next match rotates the secret
        fake_2 = FakeRedis({gamelib.PER_MATCH_FLAG_KEY_REDIS_KEY: self.SECRET_2.hex().encode('ascii')})
        with patch('gamelib.gamelib.get_redis_connection', return_value=fake_2):
            self.assertEqual(service.check_flag(flag), (None, None, None, None))


if __name__ == '__main__':
    unittest.main()
