rule Win_Trojan_SdBot_3855
{
strings:
	$a0 = { 55c6de100ed1734c807994e3b14705f6e6d6ad4a1cc55edaef20182d8b135435b1b8ce5b93f232b5ed970fac3835b72a3f010c7b603f0f24c913b9dba86a137a447bbf8fa2d56eccd0d30b3be004fd88dfccaa1782 }

condition:
	$a0
}

        
