rule Win_Spyware_Banker_2635
{
strings:
	$a0 = { bda7e8b2cefb401be7e2070ee967d363f44b61af8afb91dec306bf4e08cd26cc21672b072737a2b11000cc3ee0c6af423be3028cbea80cfa566a2b49140bb350b251bdb1577698a9292a6dd3d791eb549698c4d3f7ed3b504a2910b2810a455db9aaccdc3f7f5d000179cc41 }

condition:
	$a0
}

        
