rule Win_Trojan_FakeAV_114
{
strings:
	$a0 = { 7249318d14ffffff298d74ffffffba160a00002155c809ca09ca239548ffffff1b9548feffff81c1001a000041ff855cffffffff856cffffffff8564feffff899560ffffff119558ffffff31956cffffff2195c8feffff83c1648b4dc829c109c10985cc }

condition:
	$a0
}

        
