rule Win_Downloader_Adload_59
{
strings:
	$a0 = { d51e19c747aa85a5d4d5c03fa79dcdaa5a709f164460980bde8d958eaa53517d8d0187a0949ed00494c7faaad7d5b3a3e9d57dcf4e7624cdf59567d5de8ba190ec1f8eea904eee67ea4fa214acce5ef24deac0d5a5d5d58c67d52c66709fd54787bb709dd5ece3bca5dbbe14920d2491d5d51156ea8cd53ea3ed07d5c0d5d56d6e6eec899d37c18ed1a392dd8ee3ea501216846f }

condition:
	$a0
}

        