rule Win_Downloader_Delf_1493
{
strings:
	$a0 = { 0054e80793f644242c0174050fb75c24b42ed816308bc3445bc31f3ebe4cd0cc70c8709f1f8b0fc470c0bc64819d9fb8b45356becc6527981300833e00753a6844066a0090130062df8bc885c9750533c05e742c082ea1c88901890d0b00000033d28bc203c08d44c1048b1e891889064283fa6475ec8b068b108916da902eae90894004ca04aef58bf28bd8 }

condition:
	$a0
}

        