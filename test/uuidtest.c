#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

const char *base = "00000000-0000-1000-8000-00805F9B34FB";

uint8_t xbase[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb};

uint16_t sixteen = 0x1234;
const char *uuidsixteen128 = "00001234-0000-1000-8000-00805F9B34FB";
const char *uuidsixteen16 = "0x1234";
const char *uuidsixteen16a = "1234";

uint8_t xuuidsixteen[] = {0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb};

uint32_t thirtytwo = 0x12345678;
const char *uuidthirtytwo32 = "0x12345678";
const char *uuidthirtytwo32a = "12345678";
const char *uuidthirtytwo128 = "12345678-0000-1000-8000-00805F9B34FB";

uint8_t xuuidthirtytwo[] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb};

const char *malformed[] = {
	"0",
	"01",
	"012",
	"xxxx",
	"xxxxx",
	"0xxxxx",
	"0123456",
	"012g4567",
	"012345678",
	"0x234567u9",
	"01234567890",
	"00001234-0000-1000-8000-00805F9B34F",
	"00001234-0000-1000-8000 00805F9B34FB",
	"00001234-0000-1000-8000-00805F9B34FBC",
	"00001234-0000-1000-800G-00805F9B34FB",
	NULL,
	};

int main(int argc, char *argv[])
{
	bt_uuid_t u, u2, u3, u4, u5, ub, u128;
	uint128_t n, i;
	char buf[512];
	int s;

	memcpy(&n, xbase, 16);
	ntoh128(&n, &i);

	if (bt_string_to_uuid(&u, base)) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_string_to_uuid(&ub, base)) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (ub.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (memcmp(&u.value.u128, &i, 16) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (memcmp(&ub.value.u128, &i, 16) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (memcmp(&ub.value.u128, &u.value.u128, 16) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &ub) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	bt_uuid_to_string(&u, buf, sizeof(buf));
	/* printf("%s\n", buf); */

	if (strcasecmp(buf, base) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	memcpy(&n, xuuidsixteen, 16);
	ntoh128(&n, &i);

	bt_uuid16_create(&u, sixteen);
	bt_uuid_to_uuid128(&u, &u128);

	if (bt_string_to_uuid(&u2, uuidsixteen16)) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_string_to_uuid(&u3, uuidsixteen16a)) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_string_to_uuid(&u4, uuidsixteen128)) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	bt_uuid128_create(&u5, i);

	if (u.type != 16) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u128.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u.value.u16 != sixteen) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u2.type != 16) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u3.type != 16) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u4.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u5.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &u2) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u2, &u3) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &u3) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u3, &u4) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u4, &u5) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u5, &u) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &ub) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u5, &ub) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &u128) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&ub, &u128) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	memcpy(&n, xuuidthirtytwo, 16);
	ntoh128(&n, &i);

	bt_uuid32_create(&u, thirtytwo);
	bt_uuid_to_uuid128(&u, &u128);
	bt_string_to_uuid(&u2, uuidthirtytwo32);
	bt_string_to_uuid(&u3, uuidthirtytwo32a);
	bt_string_to_uuid(&u4, uuidthirtytwo128);
	bt_uuid128_create(&u5, i);

	/*
	bt_uuid_to_string(&u2, buf, sizeof(buf));
	printf("%s\n", buf);

	bt_uuid_to_string(&u3, buf, sizeof(buf));
	printf("%s\n", buf);

	bt_uuid_to_string(&u4, buf, sizeof(buf));
	printf("%s\n", buf);
	*/

	if (u.type != 32) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u128.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u.value.u32 != thirtytwo) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u2.type != 32) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u3.type != 32) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u4.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (u5.type != 128) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &u2) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u2, &u3) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u3, &u4) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u4, &u5) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u5, &u) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &ub) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u5, &ub) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&u, &u128) != 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	if (bt_uuid_cmp(&ub, &u128) == 0) {
		printf("Fail %d\n", __LINE__);
		return 1;
	}

	for (s = 0; malformed[s]; ++s) {
		if (bt_string_to_uuid(&u3, malformed[s]) == 0) {
			printf("Fail %s %d\n", malformed[s], __LINE__);
			return 1;
		}
	}

	return 0;
}
