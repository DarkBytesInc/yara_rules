rule Win_Tool_CreateExt_1
{
strings:
	$a0 = { 01ff7420416e6faa2004f53d895c57736b576f168997601c8cbfa819a6a95d6349d76878b6ed864ddea184845068881468b8088b8be227362c0cb3ea538c2a08 }

condition:
	$a0
}

        
