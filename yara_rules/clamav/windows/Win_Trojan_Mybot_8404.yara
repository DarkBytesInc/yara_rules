rule Win_Trojan_Mybot_8404
{
strings:
	$a0 = { 744ba1ec57e78348fe4d5cda03e927763f421dad3edf1a311b15736337becd6c801b193b52e35a447f638400f1c27c8a3889a8fc98a8d338fffa42672c6154b03ec04613d55d747d9e9957b682efd27fab038c1092 }

condition:
	$a0
}

        