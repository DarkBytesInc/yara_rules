rule Win_Trojan_DNSChanger_121
{
strings:
	$a0 = { 8bcaed0f868d7f124b0b5bf47f2f1be3fef7f4f4528fcb527e22f47f2f07e31ff4f4f48fcb527f10868daf104b0b5bf47f2f1be399f4f4f4528fcb527f0e610a5355c888c3f455c85e80e75a886ef70b5d807e038efd7f7b5df41e4f1a4b0b8ecb7f6e5d }

condition:
	$a0
}

        
