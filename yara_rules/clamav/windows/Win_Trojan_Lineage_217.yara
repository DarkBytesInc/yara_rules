rule Win_Trojan_Lineage_217
{
strings:
	$a0 = { 295db48a3fa6cef4ce2236ed94b72e0dc2ba63b914baa82fb2a3f7243cc8a919f6ea53d674f418ab3e5d76545106e1e00590d163b165d125ecf831b3f786048c7c8ff93e46e62952c9569e86d057c6dea14252e70fbc236bdee6ee1aa2bd0d31614baff15c02580dfe5ee93e3129594b6a56f79cd5d51355ce6e3961350abe85 }

condition:
	$a0
}

        