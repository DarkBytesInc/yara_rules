rule Win_Trojan_Startpage_16
{
strings:
	$a0 = { 736269616e546f6f6c626172506f70757000476f00004e6f000059657300266e6963653d0000266e696368653d00434f4d424f424f580000000012e0020000000000c0000000000000464601000000000000c000000000000046e2710110a99b001068b60010485901105658 }

condition:
	$a0
}

        