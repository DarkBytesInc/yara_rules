rule Win_Trojan_FakeAV_119
{
strings:
	$a0 = { 29c9198d50fdffff198d0cffffff238dd8feffff338d30feffff31ca81ea000600001995c8feffff1995fcfeffff1b95c0fdffff0395a4fdffff03957cfdffff01ca118d10fdffffff850cffffff298dfcfcffffff15b4e14000ba5d060000138568ffff }

condition:
	$a0
}

        
