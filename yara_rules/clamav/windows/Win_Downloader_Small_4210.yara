rule Win_Downloader_Small_4210
{
strings:
	$a0 = { 0054e80593f644242c0174050fb75c24b42ed816308bc3445bc31f3ebe4cbcb870b4709f1f8b0fb070aca864819d9fa4a05356becc6527981300833e00753a6844066a0090130062df8bc885c9750533c05e742c082ea1c88901890d0b00000033d28bc203c08d44c1048b1e891889064283fa6475ec8b068b108916d66b03ae908900894004092a13b88bf2 }

condition:
	$a0
}

        