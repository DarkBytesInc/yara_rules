rule Win_Trojan_Spambot_180
{
strings:
	$a0 = { 333360b03319ff101fc8229dcde8ff3f01f8e4477ed0bc8dd017091cb9139c18f72e42fffffff551336b3867dd175950d7891294d19ce92ef5fa54aeae10052ad5ffffffff2a793ece8cad735c0abbb57713ad55bbe737cfee34d19a1e10a179cdad9137e3ffd7ffff1a5904a584 }

condition:
	$a0
}

        
