rule Win_Trojan_Delf_1140
{
strings:
	$a0 = { 5e716cb86ff52a84d807e7874ea41255bc1fba1d6e2aeb92d7813398a919da202185381a6e118932dbd2a5f8da89f2c528a4fa233a9647cc5748228a54b1a60228 }

condition:
	$a0
}

        
