rule Win_Trojan_SdBot_2283
{
strings:
	$a0 = { 1cad268c13d3218f8cab70e74f32940d3f4cd69baac438363ab3aa7c9f89b740690324775eb9a693e855d7228d3c236dde9fd194ac72e3f0d2840d32a7cd52fd63b02f2b2f4c55c253154ce2d0cb7cac0360e30323f206f93ff1a7d1b2df76ad39addc }

condition:
	$a0
}

        
