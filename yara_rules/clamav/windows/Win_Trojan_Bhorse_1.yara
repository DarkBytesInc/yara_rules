rule Win_Trojan_Bhorse_1
{
strings:
	$a0 = { 1c9049424d2020332e330002020100027000d002fd0200090002000000fc2bc08ed8bd007cfa8ed08be5fb5055a113 }

condition:
	$a0
}

        
