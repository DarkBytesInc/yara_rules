rule Doc_Trojan_Novosib_1
{
strings:
	$a0 = { 67203d2022cff0eee8e7eef8ebe020eaf0e8f2e8f7e5f1eae0ff20eef8e8e1eae02ecfe5f0e5e7e0eff3f1f2e8f2e520eff0e8ebeee6e5ede8e52e2022 }
	$a1 = { 632e5b46696c654e616d65245d2829202b20223a46616e746f6d222c20224e6f726d616c3a46616e746f6d22 }

condition:
	$a0 and $a1
}

        
