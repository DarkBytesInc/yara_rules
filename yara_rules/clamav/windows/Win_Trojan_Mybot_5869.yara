rule Win_Trojan_Mybot_5869
{
strings:
	$a0 = { eed7404db253b259b2603bb17eb184b1eac1ef4b35a46065c7f6a83a5b4b4bbf690127803f5371e46aea94ef25154b2f7049aaacc52a0ccda8d626dca5e42377eb01f38607360b2217400d275d2fa80740b89e284a175a976272627c6282628b608f5e9a5c9e30b67ec5d4cdeac3db0db2d1e716f634fa5200d36f078d1c9e6045d55b891083bc9cd4f4e8803586b4528b6e907eea1f }

condition:
	$a0
}

        