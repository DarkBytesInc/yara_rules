rule Win_Trojan_Agent_34912
{
strings:
	$a0 = { f2eef4efb83e2deb10eb949aa6c2e89fba6a34f50abef5e6e283b5ecaf96bba7c5e2465ebf6af4ee89d008d49c98bcfbdced2c35644ecce1bfd5f4ffa2edd8e0c6dfefdee4c242390eb4e0d483c4f5d89bb1befb8e94ff8f0ad1 }

condition:
	$a0
}

        
