rule Win_Trojan_Agent_31748
{
strings:
	$a0 = { c08b1314606425ffc08b1314606025ffc08b1314605c25ffc08b1314605825ffc08b1314609425ffc08b1314605425ffc08b1314605025ffc08b13144030a150a1501314131455900001e85090c3030053d88b53144030a101e083135590a150e8501314130000011b01f88383d8f7c0c35b7fe030a1505283131440a15000e0131455900001e85090c30b00 }

condition:
	$a0
}

        