rule Win_Trojan_Keylogger_160
{
strings:
	$a0 = { a67ea2887db05df5e9d752fa78dd0b71adb3d52ba58f49203e6c435bb5e5d1a6ec1e5ea3053d6569814b1bea0add470853ea6ac452f39479186433bdfaeb30cf30fad1bee7127360c2e14d2308d7467d509377e2a6d68c3c75cba81a6270540fa0e54bb37237498cf067e7b3c79279faf62ae83d7a16b5f7655c85d727846ddde9d437b9533fd5f0a15bc6d1 }

condition:
	$a0
}

        