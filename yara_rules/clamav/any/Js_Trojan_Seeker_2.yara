rule Js_Trojan_Seeker_2
{
strings:
	$a0 = { 7374723d273e7565746b7276226e637069776369673f244c5565746b72762440220f0c57544e3f246a7676723c31317979793072776a3074773175676374656a306a766f6e243d0f0c667165776f6770763079746b76672a243e4352524e4756224a474b494a563f32 }

condition:
	$a0
}

        