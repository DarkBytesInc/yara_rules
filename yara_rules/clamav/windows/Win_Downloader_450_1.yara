rule Win_Downloader_450_1
{
strings:
	$a0 = { 96704f80ecc42f304c6caeb1e6ec5a1107f476b7dbde12f59010e80b302c073b59186cbac085c08ae8689806d93ec28f2f206a0a2be4e467dfe440e4242852e0835cf220e0bad4e0e0810c7621dc2bdcece00ed8dc5268f4f5f555253f276b7c5d7044dcba09e5bf1d28c500687474703a2f2f }

condition:
	$a0
}

        