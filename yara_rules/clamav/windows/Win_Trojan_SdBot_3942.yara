rule Win_Trojan_SdBot_3942
{
strings:
	$a0 = { f5dd16cd2a6cfd4af082da45d4bd59e85700626dc52aac43ab4f70b7a512b34bc75a9d09b1ec687fa5f0868a4777413c4fa91c76c0b422ba931adf6de91832c5da372b86b57dacaaea7d3750b8143191a651d0bcbb16d9028be54360 }

condition:
	$a0
}

        
