rule Win_Downloader_Small_3604
{
strings:
	$a0 = { f32c282460f3f3f3f3205c1c18f3f3f3f314100c08f3f3f3f304706c68d0f1f3f37800fc8053838885d30cc4bcbb0a54e805c1b60000fbf644242c0174050fb75c24308bc3445bc31cb7a375f87e7e7e7ef4f0ece805767e7ee4e0dc5356bed075604e0090833e00753a6844066a009c00909d015f8bc885c9750533c05e63417081a1cc8901890d000000a0 }

condition:
	$a0
}

        