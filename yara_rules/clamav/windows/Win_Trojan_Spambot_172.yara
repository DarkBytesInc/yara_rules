rule Win_Trojan_Spambot_172
{
strings:
	$a0 = { ae9c0501a1ee186d5775cef0ffffffebd40ddd8567b4d982804c5698a311b093e0c3015a0cbfbd57aed108ffffff0f35d985819aef845b09b7312296529980f1f8dc483867ddc59853728cffffff58d52a4efe462e469be2df11cd312ac831109dc0afead93778ffff079f5fcab6 }

condition:
	$a0
}

        
