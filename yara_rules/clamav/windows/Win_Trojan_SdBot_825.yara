rule Win_Trojan_SdBot_825
{
strings:
	$a0 = { 54b83d817028ec519600fde23e20b5e8c34100c81df03c9017290176802e24ffaa1f5b807c706aa2aeaba0f41cd200c3a10ae0524d5882093174cfe980876b6514b900c9d332080e5934960150c64241495818e035d90022df0c59289a503b005b1a3d17bf88351400b053bc41ff732a1c2683b13d005152914e935b054d62992148c03954502300e8727f32f1d3285a6084c8458902 }

condition:
	$a0
}

        