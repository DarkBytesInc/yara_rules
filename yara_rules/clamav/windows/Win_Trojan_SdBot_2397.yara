rule Win_Trojan_SdBot_2397
{
strings:
	$a0 = { 3198621ca7dc5ddbb55ddd6cb5d62d77a30d134b118500cb0acb8c9212cbea3541854a8a4accf73ccfbdafd70c3feabd9feff7cf6f8f645ef7dc737f9dfbebdc73cf3977a6b7657ab63d678fcd9269483efd76636ca6c167edb0dbeccacd06b3c16eb7071e35066e080cb16db71a525d }

condition:
	$a0
}

        
